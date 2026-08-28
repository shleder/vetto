# Инженерный каталог системных требований, отказоустойчивых паттернов и векторов изоляции AI-агентов кодогенерации

## 1. Системный вердикт и архитектурный манифест

Автономные локальные AI-агенты кодогенерации (Claude Code, OpenAI Codex, Cursor IDE, Aider, Cline, OpenHands) представляют собой принципиально новый класс недоверенных многопроцессных рабочих нагрузок. В отличие от детерминированных CI/CD-скриптов, агент выполняет недетерминированные итерации в цикле обратной связи: динамически исследует файловую систему хоста, компилирует код, запускает локальные тестовые серверы, форкает субагенты, обращается к внешним сетевым API и модифицирует собственное состояние.

Традиционные подходы к изоляции (тяжеловесные Docker-контейнеры или запуск без ограничений в среде разработчика) демонстрируют фатальную несовместимость:
1. **Тяжелые контейнеры (Docker/Podman)** нарушают интероперабельность с хостовыми инструментами (Go TLS cert verification через Mach IPC, VS Code PTY streaming, WSL2 VFS mounts), требуют запуска постоянных привилегированных демонов и вносят задержки в 200–500 мс на вызов.
2. **Отсутствие изоляции** приводит к компрометации приватных ключей (`~/.ssh`, `~/.aws`, `.env`), захвату портов отладки браузера (`localhost:9222`), неконтролируемым форк-бомбам, раздуванию дисковых хранилищ транскриптов до сотен гигабайт и необратимому повреждению баз данных SQLite/JSONL при аварийном завершении процессов.

Ниже представлен исчерпывающий каталог из 50 подтвержденных инженерных требований, декомпозированных на 4 технологических трека:
- **R1 (Пункты #1–#15)**: Изоляция на уровне ядра ОС и хостовые примитивы безопасности (Linux Landlock ABI v1–v6, Seccomp-BPF, User/Mount/PID Namespaces, macOS Seatbelt SBPL / Endpoint Security, Windows AppContainer / Job Objects).
- **R2 (Пункты #16–#30)**: Инструментарий разработки и интероперабельность рантаймов (Go TLS, Git over SSH, барьеры рекурсии подоболочек, Zero-Overhead PTY Aho-Corasick & Shannon entropy redactors, IDE statusline shims, менеджеры пакетов npm, cargo, uv, pnpm, bun, DebugPortGuard, DNS rebinding pinning).
- **R3 (Пункты #31–#40)**: Мульти-агентная конкурентность, повреждение персистентного состояния и восстановление сессий (OFD locks, cross-VFS WAL recovery на WSL2/9P, защита от раздувания base64-снимков, восстановление хвостов JSONL, монотонный ре-секвенсинг ординалов, исправление SQLite `ItemTable` в Cursor `state.vscdb`, зачистка процессов-сирот через PDEATHSIG, двухфазный откат с бэкапами).
- **R4 (Пункты #41–#50)**: Корпоративные политики, операционные гарды и регуляторный комплаенс (7-уровневая детерминированная иерархия, enterprise lockdown, субтрактивные deny-маски поверх Landlock, HMAC-SHA256 chained audit, экспорт телеметрии SARIF 2.1.0, архитектура zero-daemon и zero-telemetry, контекстные условия с лимитами бюджетов сканирования, изоляция параллельных субагентов).

---

## 2. Каталог требований: Трек R1 — Изоляция на уровне ядра ОС и примитивы безопасности хоста

### #1. Linux Landlock ABI v1–v3: Аддитивное разграничение файлового доступа и нормализация масок дескрипторов
- **Симптом разработчика и сценарий сбоя**:
  При попытке ограничить доступ агента к конфиденциальным файлам (`.env`, `~/.ssh/id_ed25519`, `credentials.json`), расположенным внутри рабочего каталога проекта (`$PROJECT`), Landlock не позволяет задать субтрактивное правило «запретить чтение конкретного файла внутри разрешенного родительского каталога». Все правила Landlock являются аддитивными (allowlist). Если среда пытается имитировать запрет без пространства имен монтирования, агент получает несанкционированный доступ. При попытке применить каталожные маски (например, `LANDLOCK_ACCESS_FS_READ_DIR`) к файловым дескрипторам системный вызов падает с ошибкой `EINVAL`.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системные вызовы:
    - `syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0)` (syscall 444 на x86_64/aarch64).
    - `syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0)` (syscall 445).
    - `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
    - `syscall(SYS_landlock_restrict_self, ruleset_fd, 0)` (syscall 446).
  - Маски прав доступа:
    - ABI v1 (Linux 5.13): `LANDLOCK_ACCESS_FS_EXECUTE` (1<<0), `WRITE_FILE` (1<<1), `READ_FILE` (1<<2), `READ_DIR` (1<<3), `REMOVE_DIR` (1<<4), `REMOVE_FILE` (1<<5), `MAKE_CHAR` (1<<6), `MAKE_DIR` (1<<7), `MAKE_REG` (1<<8), `MAKE_SOCK` (1<<9), `MAKE_FIFO` (1<<10), `MAKE_BLOCK` (1<<11), `MAKE_SYM` (1<<12).
    - ABI v2 (Linux 5.19): `LANDLOCK_ACCESS_FS_REFER` (1<<13) — перемещение/связывание файлов между директориями.
    - ABI v3 (Linux 6.2): `LANDLOCK_ACCESS_FS_TRUNCATE` (1<<14) — усечение файлов через `ftruncate`/`truncate`.
  - Нормализация: для регулярных файлов применяется маска `READ_FILE | WRITE_FILE | EXECUTE | TRUNCATE`, исключающая флаги каталогов и предотвращающая `EINVAL`.
- **Программные критерии верификации**:
  - `assert_eq!(ruleset_attr_size_for_abi(1), 8);`
  - `assert_eq!(ruleset_attr_size_for_abi(2), 8);`
  - `assert_eq!(ruleset_attr_size_for_abi(3), 8);`
  - `assert_ne!(handled_fs_mask(2) & REFER, 0);`
  - `assert_ne!(handled_fs_mask(3) & TRUNCATE, 0);`
  - Проверка алгоритма формирования правил: для каталогов записи флаг `strip_read_on_write` исключает `READ_FILE` для предотвращения неявного чтения исключенных узлов.

---

### #2. Linux Landlock ABI v4: Ограничение сетевых портов TCP (`BIND_TCP`, `CONNECT_TCP`)
- **Симптом разработчика и сценарий сбоя**:
  Агент исполняет вредоносную или скомпрометированную зависимость, открывающую сетевой бэкдор (`bind` на `0.0.0.0:8080`) или совершающую исходящие подключения (`connect`) к неавторизованным удаленным C2-серверам или внутренним облачным метаданным (`169.254.169.254:80`). Без контроля сетевых портов агент действует с полными сетевыми привилегиями пользователя.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Структура `LandlockRulesetAttr` расширяется до 16 байт (`handled_access_net: u64`).
  - Константы: `LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0`, `LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1` (Linux 6.7+, ABI v4).
  - Регистрация правила: `SYS_landlock_add_rule` с `rule_type = LANDLOCK_RULE_NET_PORT (2)` и структурой `LandlockNetPortAttr { allowed_access: u64, port: u64 }`.
- **Программные критерии верификации**:
  - `assert_eq!(std::mem::size_of::<LandlockNetPortAttr>(), 16);`
  - `assert_eq!(ruleset_attr_size_for_abi(4), 16);`
  - `assert_eq!(handled_net_mask(4), LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP);`
  - Статический отказ при передаче портов > 65535 или отрицательных дескрипторов.

---

### #3. Linux Landlock ABI v5: Контроль символьных устройств и ioctl (`IOCTL_DEV`) для PTY
- **Симптом разработчика и сценарий сбоя**:
  Интерактивные агенты (Claude Code CLI, Cursor interactive terminal) падают с ошибками `EPERM` или `ENOTTY` при попытке перенастройки размера терминала (`ioctl(TIOCSWINSZ)`), захвата управляющего терминала (`TIOCSCTTY`) или чтения из `/dev/ptmx`, `/dev/pts/*`, `/dev/tty`. Это происходит из-за того, что на ядрах Linux 6.10+ (ABI v5) право `IOCTL_DEV` включается в ruleset, но символьные устройства терминала не были явно разрешены.
- **Затронутые среды агентов**: Claude Code, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Флаг: `LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15` (Linux 6.10+, ABI v5).
  - Явное добавление путей `/dev/ptmx`, `/dev/pts`, `/dev/tty` в ruleset через открытие с флагами `O_PATH | O_CLOEXEC` и передачей прав `READ_FILE | WRITE_FILE | IOCTL_DEV` (для файлов) и `READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV` (для каталогов).
- **Программные критерии верификации**:
  - `assert_ne!(write_rights(5) & IOCTL_DEV, 0);`
  - `assert_ne!(handled_fs_mask(5) & IOCTL_DEV, 0);`
  - Модульный тест `add_pty_whitelist`: проверка открытия дескрипторов и корректная обработка `EEXIST`.

---

### #4. Linux Landlock ABI v6: Изоляция абстрактных сокетов (`ABSTRACT_UNIX_SOCKET`) и сигналов (`SIGNAL`)
- **Симптом разработчика и сценарий сбоя**:
  Агент осуществляет горизонтальное перемещение (lateral movement) через подключение к абстрактным Unix-сокетам (начинающимся с нулевого байта `@`), открытым хостовыми демонами (например, `@/tmp/dbus-...`, `@X11`, `@docker.sock`), минуя файловую систему VFS. Также агент может отправлять сигналы `SIGKILL`/`SIGTERM` процессам пользователя за пределами песочницы при совпадающем UID.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Структура `LandlockRulesetAttr` расширяется до 24 байт (`handled_access_scope: u64`).
  - Флаги области видимости (Linux 6.12+, ABI v6):
    - `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0`
    - `LANDLOCK_SCOPE_SIGNAL = 1 << 1`
  - Создание ruleset размером 24 байта изолирует абстрактные сокеты и доставку сигналов между доменами безопасности Landlock.
- **Программные критерии верификации**:
  - `assert_eq!(ruleset_attr_size_for_abi(6), 24);`
  - `assert_eq!(handled_scope_mask(6), LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL);`
  - Классификатор сокетов: путь сокета с префиксом `@` классифицируется как `NotificationClass::Blocked`.

---

### #5. Seccomp-BPF User Notification: Наблюдаемость без инверсии исполнения (Zero-TOCTOU)
- **Симптом разработчика и сценарий сбоя**:
  Попытка использовать механизм `SECCOMP_RET_USER_NOTIF` для принудительной фильтрации или изменения аргументов системных вызовов приводит к уязвимости TOCTOU (Time-of-Check to Time-of-Use): пока процесс-супервизор считывает путь из памяти `/proc/<pid>/mem`, поток агента успевает подменить указатель. Если поток супервизора заблокирован, системные вызовы агента зависают на неопределенный срок.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Фильтр устанавливается через `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog)`.
  - Пул супервизора обрабатывает события через `ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, &notif)`.
  - Валидация актуальности: вызовы `ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id)` до и после чтения `/proc/<pid>/mem`.
  - Ответ супервизора отправляется строго с флагом `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (`ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp)`). Фактическое решение о доступе делегируется LSM-модулю Landlock в ядре.
- **Программные критерии верификации**:
  - Байткод BPF: проверка перехода `BPF_JEQ` на `SECCOMP_RET_USER_NOTIF` (опкод `0x7fc00000`).
  - Проверка валидации нативной архитектуры (`AUDIT_ARCH_X86_64` / `AUDIT_ARCH_AARCH64`) перед фильтрацией системных вызовов.

---

### #6. Seccomp ADDFD: Эмуляция системных файлов и инъекция `/dev/null`
- **Симптом разработчика и сценарий сбоя**:
  Инструменты сборки и утилиты инспекции хоста завершаются с ошибками при попытке чтения системных файлов конфигурации (`/etc/os-release`, `/etc/hostname`, `/proc/kallsyms`, `/proc/version_signature`), раскрывающих чувствительные сведения об окружении. Предоставление прямого чтения нарушает изоляцию.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Обработчик `ExactSystemFileSubstitution`: при перехвате системных вызовов семейства `open`/`openat`/`openat2` на пути из белого списка (`is_supported_system_path`), супервизор выполняет `ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_ADDFD, &addfd)`.
  - Поле `addfd.srcfd` содержит дескриптор `/dev/null`, `addfd.newfd_flags = O_CLOEXEC`.
  - Системные вызовы `execve`, `unlink`, `chmod`, `rename`, `connect` строго исключены из ADDFD-подмены.
- **Программные критерии верификации**:
  - Отклонение путей вне строгого белого списка.
  - Проверка источника через `readlink(/proc/self/fd/<fd>) == "/dev/null"`.
  - Валидация предиката `addfd_allowed_syscall(nr)`.

---

### #7. Харденинг системных вызовов Seccomp: Блокировка 28 векторов побега и разрушения песочницы
- **Симптом разработчика и сценарий сбоя**:
  Вредоносный скрипт или скомпрометированный пакет пытается размонтировать маски секретов (`umount2`), перехватить память родительского процесса (`process_vm_readv`, `ptrace`), использовать асинхронный `io_uring` для обхода хуков LSM или загрузить eBPF-программы (`bpf`), перехватывающие системные вызовы ядра.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Установка BPF-фильтра через `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog)`.
  - Блокировка с возвратом `EPERM` (`SECCOMP_RET_ERRNO | EPERM`) 28 системных вызовов:
    1. `NR_UMOUNT2`
    2. `NR_MOUNT`
    3. `NR_PIVOT_ROOT`
    4. `NR_MOVE_MOUNT`
    5. `NR_OPEN_TREE`
    6. `NR_FSOPEN`
    7. `NR_FSCONFIG`
    8. `NR_FSMOUNT`
    9. `NR_FSPICK`
    10. `NR_MOUNT_SETATTR`
    11. `NR_IO_URING_SETUP`
    12. `NR_IO_URING_ENTER`
    13. `NR_IO_URING_REGISTER`
    14. `NR_USERFAULTFD`
    15. `NR_PTRACE`
    16. `NR_PROCESS_VM_READV`
    17. `NR_PROCESS_VM_WRITEV`
    18. `NR_PIDFD_GETFD`
    19. `NR_KEXEC_LOAD`
    20. `NR_KEXEC_FILE_LOAD`
    21. `NR_INIT_MODULE`
    22. `NR_FINIT_MODULE`
    23. `NR_DELETE_MODULE`
    24. `NR_PERF_EVENT_OPEN`
    25. `NR_BPF`
    26. `NR_REBOOT`
    27. `NR_SWAPON`
    28. `NR_SWAPOFF`
  - Дополнительно вызовы с установленным битом ABI x32 (`0x40000000`) немедленно уничтожаются (`SECCOMP_RET_KILL_PROCESS`).
- **Программные критерии верификации**:
  - Статический BPF-эмулятор: возврат `EPERM` для всех 28 системных вызовов во всех режимах сетевых политик (`SocketPolicy::UnixOnly`, `SocketPolicy::UnixAndIp`).
  - Проверка немедленного уничтожения процесса при вызове с `X32_SYSCALL_BIT`.

---

### #8. Непривилегированные пользовательские пространства имен (`CLONE_NEWUSER`) и двухканальный протокол маппинга
- **Симптом разработчика и сценарий сбоя**:
  При запуске песочницы возникает состояние гонки (race condition) при записи маппингов UID/GID (`uid_map`, `gid_map`). При использовании одного двунаправленного канала дочерний процесс считывает собственный статус вместо вердикта родителя, исполняется с непривязанным UID `65534 (nobody)` и падает при попытке монтирования или создания файлов.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системный вызов: `unshare(CLONE_NEWUSER)` (флаг 0x10000000).
  - Двухканальный протокол синхронизации через два раздельных канала `pipe2(..., O_CLOEXEC)`:
    - Канал `ready_fds` (ребенок -> родитель): ребенок сигнализирует об успешном `unshare`.
    - Канал `ack_fds` (родитель -> ребенок): родитель записывает `deny` в `/proc/<pid>/setgroups`, `0 <host_uid> 1` в `/proc/<pid>/uid_map` и `0 <host_gid> 1` в `/proc/<pid>/gid_map`, после чего отправляет байт подтверждения `0`.
- **Программные критерии верификации**:
  - Статический анализ `probe_userns()`: проверка закрытия неиспользуемых концов каналов в родителе и ребенке (`ready_fds[0]`, `ready_fds[1]`, `ack_fds[0]`, `ack_fds[1]`).
  - Проверка префлайт-функций `userns_knobs_look_enabled()` (`/proc/sys/kernel/unprivileged_userns_clone`, `/proc/sys/user/max_user_namespaces`).

---

### #9. Изоляция пространств имен монтирования (`CLONE_NEWNS`) и разграничение `/dev/shm` и `/tmp`
- **Симптом разработчика и сценарий сбоя**:
  Параллельно работающие агенты или агент и процессы хоста делят общий каталог разделяемой памяти `/dev/shm` (POSIX shared memory) и `/tmp`. Агент может исчерпать оперативную память хоста, прочитать тензоры PyTorch других процессов или перетереть временные файлы. При монтировании масок секретов без перевода точек в приватные (`MS_PRIVATE`) события монтирования распространяются на хостовую ОС.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системный вызов: `unshare(CLONE_NEWNS)` (0x00020000).
  - `mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL)` — изоляция дерева монтирования.
  - Приватный `tmpfs` поверх `/dev/shm`: `mount(NULL, "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=67108864,mode=1777")` (лимит 64 МБ).
  - Приватный `tmpfs` поверх `/tmp`: `mount(NULL, "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=67108864,mode=1777")` (лимит 64 МБ).
  - Маскирование файлов: `mount("/dev/null", path, NULL, MS_BIND, NULL)`.
  - Маскирование каталогов: `mount(NULL, path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=000")`.
- **Программные критерии верификации**:
  - `assert_eq!(DEV_SHM_SIZE_BYTES, 64 * 1024 * 1024);`
  - `assert!(DEV_SHM_MOUNT_OPTIONS.contains("size=67108864"));`
  - `assert_eq!(TMP_SIZE_BYTES, 64 * 1024 * 1024);`
  - Валидация функции `mask_path`: файл маскируется bind-mount `/dev/null`, каталог — `tmpfs` с правами `000`.

---

### #10. Пространство имен PID (`CLONE_NEWPID`) и монтирование `/proc` с опцией `hidepid=2`
- **Симптом разработчика и сценарий сбоя**:
  Агент исследует `/proc` и просматривает дерево процессов хостовой системы, включая аргументы командной строки и переменные окружения других агентов (`/proc/<pid>/cmdline`, `/proc/<pid>/environ`), содержащие API-ключи и токены.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - `unshare(CLONE_NEWPID)` (0x20000000). Процесс супервизора выполняет `fork()`, становясь PID 1 внутри нового пространства имен.
  - Монтирование приватного procfs: `mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2")`.
  - При возврате ядром `EINVAL` или `ENOPROTOOPT` (устаревшие ядра без поддержки `hidepid=2`) выполняется fallback на монтирование без `hidepid` со статусом `ProcVisibility::Fallback`.
- **Программные критерии верификации**:
  - Статические тесты перечисления `ProcVisibility` (`HidePid` vs `Fallback`).
  - Валидация функции `hidepid_unsupported(errno)`: проверка кодов `EINVAL`, `ENOPROTOOPT`, `EOPNOTSUPP`.
  - Сбор дерева процессов с чтением поля 22 (`starttime`) из `/proc/<pid>/stat` для предотвращения подмены при wrap-around PID.

---

### #11. Ограничение ресурсов процесса и межпроцессного взаимодействия (`setrlimit` / `cgroup v2`)
- **Симптом разработчика и сценарий сбоя**:
  Форк-бомба агента, утечка памяти в Node.js/Python процессах или захват системных очередей сообщений POSIX (`mq_open`) и блокированной памяти (`mlock`) приводят к отказу в обслуживании (DoS) хостовой операционной системы.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Установка лимитов через `setrlimit`:
    - `setrlimit(RLIMIT_CPU, &rlimit)`
    - `setrlimit(RLIMIT_AS, &rlimit)` (адресное пространство)
    - `setrlimit(RLIMIT_NPROC, &rlimit)` (число процессов)
    - `setrlimit(RLIMIT_NOFILE, &rlimit)` (открытые дескрипторы)
    - `setrlimit(RLIMIT_MEMLOCK, &rlimit)` (блокированная память)
    - `setrlimit(RLIMIT_MSGQUEUE, &rlimit)` (очереди сообщений POSIX)
  - Равенство `rlim_cur` и `rlim_max` исключает возможность обратного повышения лимитов агентом после `execve`.
- **Программные критерии верификации**:
  - Проверка применения всех полей структуры `rlimit` в `apply_before_exec` и `apply_ipc_resource_ceilings`.
  - Валидация защиты от переполнения типов `rlim_t` на 32/64-битных ABI.

---

### #12. Нативные профили macOS Seatbelt SBPL: Динамический вызов `sandbox_init_with_parameters`
- **Симптом разработчика и сценарий сбоя**:
  Использование устаревшей утилиты `/usr/bin/sandbox-exec` приводит к сбоям на современных версиях macOS (Sequoia, Sonoma) и требует записи временных файлов профилей на диск хоста. При попытке маскирования секретов профиль SBPL без завершающих `(deny ...)` правил оставляет файлы доступными из-за перекрытия родительскими `(allow ...)` правилами.
- **Затронутые среды агентов**: Claude Code, Cursor, Codex, Aider, Cline.
- **Механизм ядра и системные вызовы**:
  - Формирование профиля SBPL в памяти:
    `(version 1)`
    `(deny default)`
    Разрешение системных библиотек (`/System`, `/Library`, `/usr/lib`, `/dev/null`, `/dev/tty`).
    Параметризованные правила: `(allow file-read* (subpath (param "ALLOW_READ_DIR_0")))`.
    Субтрактивные запреты в хвосте профиля: `(deny file-read* (subpath (param "DENY_PATH_0")))` (в SBPL действует правило «последнее совпадение побеждает»).
  - Загрузка через `dlopen("libsandbox.1.dylib", RTLD_LAZY)` и вызов `sandbox_init_with_parameters(profile_c, 0, params_array, &errorbuf)`.
- **Программные критерии верификации**:
  - Тест генерации шаблона SBPL `template_generation_contains_expected_params`: проверка параметров `ALLOW_READ_DIR_*`, `ALLOW_WRITE_DIR_*`, `DENY_PATH_*`, проверки `(deny network*)` и порядка размещения запрещающих правил в хвосте профиля.

---

### #13. macOS Endpoint Security (ES) Framework: Синхронные перехваты AUTH и тайм-ауты ядра
- **Симптом разработчика и сценарий сбоя**:
  Асинхронные уведомления FSEvents не способны предотвратить несанкционированное чтение или удаление файлов агентом (notify-only). При попытке интеграции с Endpoint Security без прав root или entitlement `com.apple.developer.endpoint-security.client` процесс падает; а при задержке ответа в AUTH-обработчике ядро macOS принудительно уничтожает процесс по сторожевому таймеру (deadlock timeout).
- **Затронутые среды агентов**: Claude Code, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Регистрация клиента через `es_new_client` с замыканием `RcBlock<dyn Fn(EsClient, *const c_void)>`.
  - Подписка на события `es_subscribe`: `ES_EVENT_TYPE_AUTH_EXEC` (0), `ES_EVENT_TYPE_AUTH_OPEN` (1), `ES_EVENT_TYPE_AUTH_RENAME` (6), `ES_EVENT_TYPE_AUTH_UNLINK` (7).
  - Синхронная оценка `evaluate_auth_event` и возврат вердикта `es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW / ES_AUTH_RESULT_DENY, cacheable)`.
  - Шлюзы проверки: `geteuid() == 0` и проверка XML-тега entitlement через `codesign --display --entitlements :-`.
- **Программные критерии верификации**:
  - Тест `capabilities()`: проверка условий `runtime_ready()`.
  - Честный fallback на Seatbelt при отсутствии прав root или entitlement (`EndpointSecurityCapabilities.reason`).

---

### #14. Windows AppContainer: Канонический порядок DACL и внедрение параметров безопасности
- **Симптом разработчика и сценарий сбоя**:
  Процессы агента на Windows запускаются без изоляции файловой системы, либо попытка настройки DACL завершается ошибкой `ERROR_INVALID_PARAMETER` из-за неканонического порядка ACE (Allow ACE расположен перед Deny ACE), в результате чего агент получает доступ к `C:\Users\<User>\.ssh` и реестру Windows.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Cline.
- **Механизм ядра и системные вызовы**:
  - Создание профиля AppContainer через `userenv!CreateAppContainerProfile`.
  - Получение SID через `DeriveAppContainerSidFromAppContainerName`.
  - Каноническое внедрение DACL: чтение `GetNamedSecurityInfoW`, формирование структуры `ExplicitAccessW` с добавлением `DENY_ACCESS` ACE перед `GRANT_ACCESS` ACE (`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`), вызов `SetEntriesInAclW` и `SetNamedSecurityInfoW`.
  - Атрибуты запуска: `InitializeProcThreadAttributeList`, `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &caps)`.
  - RAII-гарды `AppContainerProfileGuard` (удаление профиля через `DeleteAppContainerProfile`) и `DaclOverrideGuard` (восстановление оригинального дескриптора в `Drop`).
- **Программные критерии верификации**:
  - `assert_eq!(std::mem::size_of::<SidAndAttributes>(), std::mem::size_of::<usize>() * 2);`
  - Валидация констант доступа `FILE_GENERIC_READ` (0x00120089), `FILE_GENERIC_WRITE` (0x00120116), `FILE_ALL_ACCESS` (0x001F01FF), `DENY_ACCESS` (3), `GRANT_ACCESS` (1).

---

### #15. Windows Job Objects и Restricted Tokens: Запрет Breakaway и Low-Integrity
- **Симптом разработчика и сценарий сбоя**:
  Агент порождает дочерние процессы с флагом `CREATE_BREAKAWAY_FROM_JOB` или дублирует первичный токен безопасности, выходя из-под контроля супервизора. При завершении сессии фоновые процессы продолжают бесконтрольно исполняться на машине пользователя.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Создание Job Object: `CreateJobObjectW(NULL, NULL)`.
  - Установка ограничений через `SetInformationJobObject` с классом `JobObjectExtendedLimitInformation`: флаги `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (0x2000)` и `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION (0x400)`. Флаг `JOB_OBJECT_LIMIT_BREAKAWAY_OK` строго исключен.
  - Привязка процесса: `AssignProcessToJobObject(job_handle, process_handle)`.
  - Создание ограниченного токена: `CreateRestrictedToken(source_token, DISABLE_MAX_PRIVILEGE | LUA_TOKEN, ...)` и дублирование через `DuplicateTokenEx` с `TOKEN_ASSIGN_PRIMARY`.
  - Понижение уровня целостности (Integrity Level): вызов `SetTokenInformation(token, TokenIntegrityLevel, &label, len)` с `SECURITY_MANDATORY_LOW_RID (0x1000)`.
- **Программные критерии верификации**:
  - `assert_eq!(kill_contract(), "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | NO_BREAKAWAY");`
  - `assert_eq!(SECURITY_MANDATORY_LOW_RID, 0x1000);`
  - Проверка функции `create_primary` на обязательное наличие флагов `DISABLE_MAX_PRIVILEGE | LUA_TOKEN`.

---

## 3. Каталог требований: Трек R2 — Инструментарий разработки и интероперабельность рантаймов

### #16. Валидация TLS сертификатов в Go и Mach IPC шлюз `com.apple.trustd.agent`
- **Симптом разработчика и сценарий сбоя**:
  Инструменты на базе Go (`go get`, `go build`, `gh`, `golangci-lint`), запускаемые агентом под macOS Seatbelt, зависают или падают с фатальной ошибкой `x509: certificate signed by unknown authority` при выполнении любого HTTPS-запроса, так как рантайм Go пытается валидировать сертификаты через обращение к системным Mach-сервисам `com.apple.trustd.agent` и `com.apple.SecurityServer`.
- **Затронутые среды агентов**: Claude Code, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - macOS Mach IPC: вызовы `mach_port_t`, `bootstrap_look_up()`.
  - В профиль Seatbelt SBPL включается директива:
    `(allow mach-lookup (global-name "com.apple.trustd.agent") (global-name "com.apple.SecurityServer"))`.
  - Для полностью изолированных окружений без Mach-доступа активируется переменная окружения `SSL_CERT_FILE=/etc/ssl/cert.pem` (или путь к статическому бандлу CA), переключающая рантайм Go на встроенный парсер сертификатов X.509.
- **Программные критерии верификации**:
  - Проверка генератора SBPL на обязательное включение Mach-lookup правил для `trustd.agent` при разрешении сетевых профилей.
  - Проверка инъекции переменной `SSL_CERT_FILE` в модуль сборки окружения.

---

### #17. Маршрутизация Git over SSH (порт 22) через строгие прокси-брокеры
- **Симптом разработчика и сценарий сбоя**:
  Команды `git clone git@github.com:...` или `git fetch` падают с ошибкой `ssh: connect to host github.com port 22: Connection refused` или зависают по таймауту, так как клиент OpenSSH не умеет прозрачно работать через стандартные HTTP CONNECT прокси без специального хелпера.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - На Linux FULL создается изолированный сокет `AF_UNIX`, связанный с хостовым брокером. Для процесса `git`/`ssh` конфигурируется параметр `ProxyCommand vetto net-proxy --connect %h:%p`.
  - Хелпер `net-proxy` соединяется с брокером через дескриптор Unix-сокета, выполняет валидацию strict-политики (`github.com:22`), инициирует `CONNECT` и переходит в режим прозрачной двунаправленной прокачки сырых байт SSH (opaque byte pump) без расшифровки и без генерации MITM-сертификатов.
- **Программные критерии верификации**:
  - Тесты синтаксического анализа конфигурации `ProxyCommand` в `net_relay.rs`.
  - Проверка strict-парсера: отклонение портов, отличных от разрешенного 22 для SSH-хостов.

---

### #18. Выполнение вложенных подоболочек (`x=$(gh api ...)`) и барьер рекурсии
- **Симптом разработчика и сценарий сбоя**:
  Сложные bash-скрипты, запускаемые агентами, содержат подстановки команд `$(...)`, конвейеры `|` или вызовы через обертки CLI. При наличии глобальных shim-перехватчиков в `$PATH` вложенный вызов пытается повторно инициализировать песочницу, вызывая циклическую рекурсию, исчерпание дескрипторов процессов и зависание агента.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системные вызовы конвейеров: `pipe2(O_CLOEXEC)`, `fork()`, `dup2()`, `execve()`.
  - Установка барьера рекурсии через переменные окружения: `VETTO_SANDBOXED=1` и `VETTO_SHIM_ACTIVE=1`.
  - При вызове любого shim-бинаря (`git`, `node`) функция `is_sandboxed()` проверяет наличие флагов; при их наличии поиск реального исполняемого файла исключает каталоги `.vetto/shims` и передает исполнение напрямую через `execve` без создания промежуточных слоев.
- **Программные критерии верификации**:
  - `assert!(is_shim_directory(Path::new("/home/user/.vetto/shims")));`
  - `assert!(!is_shim_directory(Path::new("/usr/bin")));`
  - Тест `recursion_barrier_checks_environment`: переключение поведения `is_sandboxed()` в зависимости от переменных окружения.

---

### #19. Потоковая PTY-маскировка секретов на базе автомата Ахо-Корасик (Zero-Overhead)
- **Симптом разработчика и сценарий сбоя**:
  Агент случайно или намеренно выводит в консоль токены доступа (`sk-ant-...`, `ghp_...`, `AKIA...`) или закрытые SSH/RSA-ключи. Использование регулярных выражений на каждом PTY-чанке вносит задержки в 50–200 мс, вызывая рывки в TUI-интерфейсе и ломая эскейп-последовательности ANSI. Замена секретов строкой `[REDACTED]` другой длины смещает координаты курсора и ломает псевдографику терминала.
- **Затронутые среды агентов**: Claude Code, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Неблокирующее чтение/запись PTY-потока через `termios` и `epoll`/`select`.
  - Построение детерминированного автомата Ахо-Корасик с 23 префиксными шаблонами (токены Anthropic, OpenAI, GitHub, AWS, Slack, GitLab, HuggingFace, PEM-заголовки).
  - Буфер переноса (carry-over buffer) фиксированного размера 256 байт для надежного перехвата секретов, разорванных границей чанка `read()`.
  - Режим маскирования `PadMask`: замена тела секрета символами `*` строго той же длины, сохраняющая ширину колонок терминала.
- **Программные критерии верификации**:
  - `assert_eq!(output.len(), secret.len());` (PadMask сохраняет размер).
  - Тест `test_chunk_split_boundary_carry_over`: проверка корректности маскирования токена `ghp_...`, разделенного пополам между двумя последовательными вызовами `redact_chunk()`.

---

### #20. Фильтрация секретов по энтропии Шеннона с подавлением ложных срабатываний
- **Симптом разработчика и сценарий сбоя**:
  Агент работает с неструктурированными секретами высокой энтропии (случайные пароли, токены без префикса). Примитивные энтропийные фильтры ошибочно маскируют валидные хэши коммитов Git (SHA-1/SHA-256), идентификаторы UUID и фрагменты base64-патчей, делая вывод git diff и логов нечитаемым.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Вычисление информационной энтропии Шеннона в скользящем окне:
    $$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
  - Порог срабатывания: $H > 4.5$ бит/байт для токенов длиной $\ge 20$ байт.
  - Белый список подавления ложных срабатываний:
    1. Hex-хэши строго фиксированной длины (32, 40, 64, 128 символов — MD5, Git SHA-1, SHA-256).
    2. Формат UUID (длина 36 символов, шаблон `8-4-4-4-12`).
    3. Чисто цифровые или монотонные строки.
- **Программные критерии верификации**:
  - `assert!((calculate_entropy(b"0123456789abcdef") - 4.0).abs() < 1e-6);`
  - `assert!(!is_entropy_masked(b"e0d123456789abcdef0123456789abcdef012345"));` (Git SHA-1 не маскируется).
  - `assert!(!is_entropy_masked(b"123e4567-e89b-12d3-a456-426614174000"));` (UUID не маскируется).
  - `assert!(is_entropy_masked(b"aB39zKmP2qL8vX1yR4wT7jN_xY9ZaBc"));` (случайный токен маскируется).

---

### #21. Шим-мультиплексирование PTY терминала для IDE и обработка `SIGWINCH`
- **Симптом разработчика и сценарий сбоя**:
  Запуск агента во встроенных терминалах VS Code, Cursor или Windsurf приводит к искажению статус-бара, потере событий изменения размера окна или нарушению работы фоновых задач IDE (tasks/terminals).
- **Затронутые среды агентов**: Cursor, Claude Code, Cline.
- **Механизм ядра и системные вызовы**:
  - Перехват размеров окна через `ioctl(fd, TIOCGWINSZ, &wsz)` и обновление через `ioctl(fd, TIOCSWINSZ, &wsz)`.
  - Установка обработчика сигнала `SIGWINCH` (`signal(SIGWINCH, handler)`).
  - Перевод родительского терминала в сырой режим (`tcgetattr`, `tcsetattr` с маской `cfmakeraw`). Резервирование ровно одной нижней строки терминала под системный статус-лайн vetto с перенаправлением остального окна псевдотерминала дочернему процессу агента.
- **Программные критерии верификации**:
  - Статические тесты `src/pty/resizer.rs` и `src/pty/ansi.rs`: валидация вычисления строк экрана (`ws_row - 1`).
  - Проверка форвардинга кодов клавиши быстрого перехода `Ctrl+]` (0x1D) для открытия оверлея событий.

---

### #22. Изоляция кэша Node.js / npm / npx и целостность lock-файлов
- **Симптом разработчика и сценарий сбоя**:
  Вызов `npm install` или `npx` внутри песочницы падает с ошибкой `EACCES: permission denied, mkdir '/home/user/.npm/_cacache'` либо повреждает глобальный кэш пользователя, вызывая несовпадение контрольных сумм в `package-lock.json` на хосте.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Изоляция переменных окружения:
    `npm_config_cache=$PROJECT/.vetto/cache/npm`
    `NPM_CONFIG_CACHE=$PROJECT/.vetto/cache/npm`
    `npm_config_prefix=$PROJECT/.vetto/cache/npm-global`
  - Разрешение прав на чтение и запись в локальный кэш проекта через Landlock/Seatbelt при сохранении строгого режима только для чтения на системный `/usr/local/lib/node_modules`.
- **Программные критерии верификации**:
  - Статическая валидация конфигурационных пресетов агентов: проверка директив переопределения переменных окружения кэша npm.

---

### #23. Многопользовательский кэш Rust / Cargo и блокировки реестра (`CARGO_HOME`)
- **Симптом разработчика и сценарий сбоя**:
  Команда `cargo build` или `cargo check` завершается ошибкой `Blocking waiting for file lock on package cache` или `failed to write /home/user/.cargo/registry/index` из-за конкуренции за глобальные блокировки `flock` между агентами или запрета записи в глобальный каталог `~/.cargo`.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Блокировки файлов `fcntl(fd, F_SETLK, &flock)` и `flock(fd, LOCK_EX)`.
  - Перенаправление `CARGO_TARGET_DIR=$PROJECT/target` и `CARGO_HOME=$PROJECT/.vetto/cargo` либо предоставление доступа только для чтения к `~/.cargo/registry` с локальным оверлеем для декомпрессии crates.
- **Программные критерии верификации**:
  - Тесты правил генерации политики Landlock: проверка предоставления прав `READ_FILE | READ_DIR | EXECUTE` для `~/.cargo/registry` и полных прав записи для `$PROJECT/target`.

---

### #24. Изоляция кэша Python pip / pipx / uv / poetry и предотвращение ошибок `EXDEV`
- **Симптом разработчика и сценарий сбоя**:
  Инструменты управления зависимостями Python (`uv`, `pip`, `poetry`) падают с ошибкой `EXDEV: cross-device link not permitted` или `PermissionError: [Errno 13] Permission denied: '/home/user/.cache/uv'` при попытке создать жесткую ссылку (hardlink) из глобального кэша колес (wheels) в изолированный каталог `.venv` на другой файловой системе (tmpfs).
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системный вызов `link()` возвращает ошибку `EXDEV` при попытке связать узлы между разными точками монтирования.
  - Инъекция переменных окружения:
    `PIP_CACHE_DIR=$PROJECT/.vetto/cache/pip`
    `UV_CACHE_DIR=$PROJECT/.vetto/cache/uv`
    `UV_LINK_MODE=copy` (принудительное копирование вместо жестких ссылок)
    `POETRY_CACHE_DIR=$PROJECT/.vetto/cache/pypoetry`
- **Программные критерии верификации**:
  - Проверка схемы политик на наличие флага `UV_LINK_MODE=copy` в среде исполнения агентов; проверка разрешений Landlock на запись в каталог `$PROJECT/.venv`.

---

### #25. Кэш pnpm Content-Addressable Store (CAS) и обход границ монтирования
- **Симптом разработчика и сценарий сбоя**:
  Менеджер пакетов `pnpm` по умолчанию использует глобальное хранилище на основе жестких ссылок (`hardlink store`). При запуске в изолированном пространстве имен монтирования вызовы создания ссылок падают с `EXDEV`, прерывая установку зависимостей.
- **Затронутые среды агентов**: Claude Code, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Системный вызов `linkat(olddirfd, oldpath, newdirfd, newpath, 0)`.
  - Переопределение конфигурации pnpm через `.npmrc` / переменные окружения: `store-dir=$PROJECT/.vetto/pnpm-store` или параметр `package-import-method=copy` / `clone-or-copy`.
- **Программные критерии верификации**:
  - Статический тест конфигурации: проверка наличия права `LANDLOCK_ACCESS_FS_REFER` (ABI >= 2) и проверки конфигурации pnpm-импорта в профиле.

---

### #26. Изоляция кэша Bun и блокировки SQLite WAL (`bun install` / `bun test`)
- **Симптом разработчика и сценарий сбоя**:
  При одновременной работе нескольких агентов или запуске `bun install` в песочнице процесс падает с ошибками блокировки базы данных SQLite (`database is locked`, код ошибки 5) или `error: FailedToLockInstallDir` из-за конкуренции за WAL-журналы в `~/.bun/install/cache`.
- **Затронутые среды агентов**: Claude Code, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Файловые блокировки открытых дескрипторов `fcntl(fd, F_OFD_SETLK, &flock)` и `mmap` на SQLite shared memory (`.shm` файлы).
  - Перенаправление каталога кэша через переменную окружения `BUN_INSTALL_CACHE_DIR=$PROJECT/.vetto/cache/bun` с изоляцией сессионных WAL-файлов.
- **Программные критерии верификации**:
  - Статический тест конфигурации профиля агента: проверка изоляции переменной `BUN_INSTALL_CACHE_DIR` и выделения приватного `tmpfs` под временные сокеты Bun.

---

### #27. Защита от перехвата локальных портов отладки (`DebugPortGuard`: Chrome DevTools, Node.js, debugpy)
- **Симптом разработчика и сценарий сбоя**:
  Агент запускает тест браузера (Playwright/Puppeteer) или скрипт, подключающийся к локальным портам отладки хоста (`localhost:9222`, `9223` для Chrome DevTools, `9229`, `9230` для Node Inspector, `5678` для Python debugpy). Это позволяет агенту скрытно перехватить реальную сессию браузера разработчика с открытыми сессиями GitHub, AWS Console и корпоративной почты.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Встроенный охранник `DebugPortGuard`. Перехват сетевых вызовов к loopback-интерфейсу.
  - Генерация криптографического токена сессии `X-Vetto-Debug-Token` вида `vdt_<sha256>`.
  - Попытка соединения с портами `9222`, `9223`, `9229`, `9230`, `5678` без совпадения токена сессии или явного включения в `allowed_ports` блокируется с вердиктом `DebugPortVerdict::Blocked` и кодом `403 Forbidden` / `ECONNREFUSED`.
- **Программные критерии верификации**:
  - `assert_eq!(guard.check_access(9222, None), DebugPortVerdict::Blocked { port: 9222, service: "Chrome DevTools" });`
  - `assert_eq!(guard.check_access(9229, None), DebugPortVerdict::Blocked { port: 9229, service: "Node.js Inspector" });`
  - `assert_eq!(guard.check_access(5678, None), DebugPortVerdict::Blocked { port: 5678, service: "Python debugpy" });`
  - Проверка успешного доступа при передаче валидного `session_token()`.

---

### #28. Предотвращение DNS Rebinding и блокировка облачных метаданных
- **Симптом разработчика и сценарий сбоя**:
  Вредоносный npm/pip-пакет выполняет DNS-запрос к подконтрольному домену, который возвращает публичный IP при первой проверке, а при реальном запросе отдает `169.254.169.254` (интерфейс метаданных AWS/GCP/Azure) или `127.0.0.1`, что позволяет украсть временные IAM-токены инстанса.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Хостовый брокер выполняет DNS-разрешение ровно один раз за пределами песочницы (`getaddrinfo`).
  - Полный набор полученных IP-адресов проверяется на принадлежность заблокированным диапазонам CIDR:
    - Loopback (`127.0.0.0/8`, `::1`)
    - Link-local / Cloud Metadata (`169.254.0.0/16`, `fe80::/10`)
    - Частные сети RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
    - Carrier-grade NAT (`100.64.0.0/10`)
  - Брокер подключается напрямую к валидированному IP без повторного DNS-запроса (DNS pinning на время TCP-сессии).
- **Программные критерии верификации**:
  - Тесты валидатора IP в сетевом брокере: отклонение адреса `169.254.169.254`, отклонение IPv4-mapped IPv6 `::ffff:169.254.169.254`, отклонение адресов `127.0.0.1` и `10.0.0.1` в режиме внешнего allowlist.

---

### #29. Сигнал смерти родителя (`PR_SET_PDEATHSIG`) и гарантированная зачистка поддерева в тире FS-ONLY
- **Симптом разработчика и сценарий сбоя**:
  В окружениях без поддержки пользовательских пространств имен (Linux FS-ONLY) аварийная остановка агента оставляет «осиротевшие» (orphaned) компиляторы, тесты или фоновые процессы, которые продолжают нагружать CPU хоста и удерживать файловые дескрипторы.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - В дочернем процессе перед `execve` вызывается `prctl(PR_SET_PDEATHSIG, SIGKILL)`.
  - Проверка состояния гонки смерти родителя: `if (getppid() != expected_ppid) exit(1);`.
  - Создание отдельной группы процессов через `setpgid(0, 0)` и отправка сигнала `kill(-pgrp, SIGKILL)` при завершении сессии супервизора.
- **Программные критерии верификации**:
  - Статический анализ кода супервизора: проверка вызова `PR_SET_PDEATHSIG` в FS-ONLY ветке; проверка обработки сигналов завершения и отправки сигналов в группу процессов `pgrp`.

---

### #30. Кросс-архитектурная трансляция номеров системных вызовов (x86_64 vs aarch64 / ARM64)
- **Симптом разработчика и сценарий сбоя**:
  Бинарный файл песочницы или BPF-фильтр, скомпилированный с жестко закодированными номерами системных вызовов x86_64 (`SYS_socket = 41`, `SYS_seccomp = 317`), запускается на машине Apple Silicon (M1/M2/M3) или AWS Graviton (ARM64, где `SYS_socket = 198`, `SYS_seccomp = 277`). В результате сетевые блокировки полностью отключаются, либо агент аварийно завершается при старте с `SIGSYS`.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Использование номеров системных вызовов исключительно из таблицы таргета `libc::SYS_*`.
  - Первая инструкция seccomp-фильтра загружает архитектуру аудита (`BPF_LD_ABS, 4`) и сверяет ее с `native_audit_arch()`:
    - `AUDIT_ARCH_X86_64 = 0xC000003E`
    - `AUDIT_ARCH_AARCH64 = 0xC00000B7`
    - `AUDIT_ARCH_I386 = 0x40000003`
    - `AUDIT_ARCH_ARM = 0x40000028`
    - `AUDIT_ARCH_RISCV64 = 0xC00000F3`
  - Несовпадение архитектуры немедленно уничтожает процесс (`SECCOMP_RET_KILL_PROCESS`).
- **Программные критерии верификации**:
  - `assert_eq!(SYS_SECCOMP, libc::SYS_seccomp);`
  - `assert_eq!(NR_SOCKET, libc::SYS_socket as u32);`
  - `assert_eq!(native_audit_arch(), 0xC00000B7);` (на aarch64).
  - Тест `foreign_arch_is_fail_closed`: проверка возврата `SECCOMP_RET_KILL_PROCESS` при несовпадении архитектуры.

---

## 4. Каталог требований: Трек R3 — Мульти-агентная конкурентность, повреждение состояния и восстановление сессий

### #31. Зависание файловых блокировок дескрипторов (OFD Locks) и коллизии зомби-процессов при параллельном доступе
- **Симптом разработчика и сценарий сбоя**:
  При аварийном завершении (`SIGKILL`, OOM-killer, закрытие IDE) одного из параллельных воркеров Claude Code или Codex файловые дескрипторы и lock-файлы (`.vetto_repair.lock`, `.session.lock`) остаются брошенными. При последующем запуске агент падает с ошибкой:
  `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"already has an active writer on session transcript"}}`
  или в консоли CLI:
  `vetto: error: lock on .../.vetto_repair.lock is held by another process (PID 48219)`.
- **Затронутые среды агентов**: Claude Code (`~/.claude/projects/**/*.jsonl`), OpenAI Codex (`~/.codex/sessions/**`), Aider, OpenHands, Cline.
- **Механизм ядра и системные вызовы**:
  - **Linux OFD Locks**: `fcntl(fd, F_OFD_SETLK, &flock)` с `fl.l_type = F_WRLCK`, `fl.l_whence = SEEK_SET`, `fl.l_start = 0`, `fl.l_len = 0`, `fl.l_pid = 0`. Ассоциированы со структурой `struct file` в ядре, не сбрасываются при закрытии соседних дескрипторов в процессе и корректно наследуются между потоками.
  - **Fallback / macOS**: `flock(fd, LOCK_EX | LOCK_NB)`.
  - **Windows**: `LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)`.
  - **Liveness Probe**: При `EACCES` / `EAGAIN` супервизор читает JSON-метаданные lock-файла (`LockMetadata { pid, acquired_at, lease_timeout_ms }`) и выполняет `kill(pid, 0)`:
    - Возврат `ESRCH` подтверждает смерть процесса: lock признается stale.
    - Проверка истечения срока аренды `now > acquired_at + (lease_timeout_ms / 1000)` предотвращает deadlock.
  - RAII-гард `SessionLockGuard`, выполняющий `fcntl(F_UNLCK)` и `unlink(lock_path)` при drop.
- **Программные критерии верификации**:
  - Сериализуемость структуры `LockMetadata { pid: u32, acquired_at: u64, lease_timeout_ms: u64 }`.
  - Наличие реализации `Drop` для `SessionLockGuard` со снятием блокировки ОС и удалением lock-файла.
  - Stale Reclaim Test: захват блокировки при мертвом PID (PID 9999999) и истекшем таймауте успешен без ошибки.
  - Contention Test: одновременное создание двух экземпляров `SessionLockGuard` на один путь возвращает ошибку конкуренции.

---

### #32. Блокировки и таймауты SQLite WAL / SHM при работе через трансляторы VFS (WSL2 / 9P / CIFS /mnt/c)
- **Симптом разработчика и сценарий сбоя**:
  При запуске Codex или Cursor в окружении WSL2, когда рабочая директория смонтирована с Windows через VFS-транслятор (`/mnt/c/...`, 9P, DrvFs, virtio-fs), операции чтения/записи в базы данных SQLite (`state_*.sqlite`, `logs_2.sqlite`, `state.vscdb`) зависают на 30–60 секунд и аварийно завершаются:
  `rusqlite::Error: database disk image is malformed (code 11)`
  `sqlite3.OperationalError: database is locked (code 5) / disk I/O error (code 10)`.
  Файлы `-wal` и `-shm` раздуваются до десятков гигабайт.
- **Затронутые среды агентов**: OpenAI Codex (`~/.codex/state_*.sqlite`), Cursor IDE (`state.vscdb`), Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Драйвер VFS Plan9 (`9pnet_virtio` / `drvfs`) не обеспечивает когерентности кэша страниц памяти между Linux и NT. Вызов `mmap` на файле `*-shm` возвращает `EINVAL` или повреждает заголовки страниц WAL.
  - Блокировки `fcntl(F_SETLK)` через 9P отбрасываются SMB-сервером, вызывая постоянный `SQLITE_BUSY`.
  - Движок восстановления `SqliteWalManager`:
    1. Обнаружение sidecar-файлов (`-wal`, `-shm`, `-journal`).
    2. Атомарное копирование базы во временный приватный каталог на локальной файловой системе (`tmpfs` / ext4).
    3. Установка `PRAGMA busy_timeout = 5000;`.
    4. Принудительный сброс и усечение журнала через `PRAGMA wal_checkpoint(TRUNCATE);`.
    5. Проверка целостности через `PRAGMA integrity_check(100);`.
    6. Открытие соединения только к проверенному снимку (`VerifiedSqliteConnection`).
- **Программные критерии верификации**:
  - Запрет прямого выполнения SQL-запросов к оригинальным путям в VFS без снимка `PrivateSqliteSnapshot`.
  - Проверка копирования всех расширений `SQLITE_SIDECAR_EXTENSIONS = ["-wal", "-shm", "-journal"]`.
  - Вызов `checkpoint_and_recover` возвращает `Ok(())` только при `PRAGMA integrity_check(100)` со статусом `ok`.
  - Запрет обработки SQLite-sidecar файлов, являющихся символическими ссылками.

---

### #33. Взрывной рост истории сессий и дублирование Base64-мультимодальных артефактов при ветвлении субагентов
- **Симптом разработчика и сценарий сбоя**:
  При ветвлении (fork) субагентов в Claude Code / OpenHands полный контекст сессии (включая скриншоты страниц, сгенерированные изображения, дампы AST) копируется в каждый дочерний транскрипт в виде Base64-строк (`data:image/png;base64,...`). За несколько итераций директория `~/.claude/projects/` вырастает до 50–150 ГБ. Агент падает:
  `vetto: error: Claude discovery exceeded the 536870912 byte budget (512 MB per-session ceiling)`
  `FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory`.
- **Затронутые среды агентов**: Claude Code (`projects/**/*.jsonl`), OpenHands, Cline, Aider.
- **Механизм ядра и системные вызовы**:
  - Массовая запись через `write()` строк размером 10–100 МБ каждая, исчерпывающая дескрипторы и дисковое пространство.
  - Лимиты бюджетов сканирования (`RescueContext`):
    - `max_session_bytes = 512 * 1024 * 1024` (512 МБ жесткий лимит на сессию).
    - `max_total_bytes = 2 * 1024 * 1024 * 1024` (2 ГБ на весь пул сканирования).
    - `max_files = 10_000` (лимит количества файлов).
  - Стриминговое восстановление:
    - Чтение через `safe_fs::read_bounded` с `O_NOFOLLOW` и проверкой `nlink == 1`.
    - Проверка неизменности хеша при повторном чтении (`read_stable` с SHA-256).
    - Экспорт и форк сессий через `O_CREAT | O_EXCL` без перезаписи существующих файлов (`source_preserved: true`).
- **Программные критерии верификации**:
  - Превышение лимита `max_session_bytes` немедленно возвращает `bail!("Claude transcript exceeds the ... byte inspection budget")`.
  - Проверка равенства `first_sha256 == second_sha256` при валидации стабильности файла.
  - Функция `snapshot` возвращает `SnapshotReceipt` с контрольной суммой `sha256` и `source_preserved == true`.

---

### #34. Повреждение хвоста JSONL-потока и компактизация неполных многострочных токенов при аварийном обрыве
- **Симптом разработчика и сценарий сбоя**:
  При внезапном прерывании процесса агента (`Ctrl+C`, `SIGKILL`, сетевой сброс соединения с LLM API) последняя строка в транскрипте JSONL оказывается недописанной (оборванной на середине ключа или литерала). При попытке возобновить сессию агент аварийно завершается:
  `SyntaxError: Unexpected end of JSON input at JSON.parse (<anonymous>)`
  `serde_json::Error("EOF while parsing a string", line: 1842, column: 94)`.
- **Затронутые среды агентов**: Claude Code (`projects/**/*.jsonl`), OpenAI Codex (`rollouts/**/*.jsonl`), Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Запись в транскрипт через `write()` без завершающего символа `\n` (`0x0A`) и без `fsync()`.
  - Алгоритм потокового восстановления (`ClaudeAdapter::repair_transcript`):
    1. Разделение байтового потока по `\n` с удалением `\r`.
    2. Валидация каждой строки через `serde_json::from_slice::<Value>`.
    3. Детектирование оборванного хвоста на последней строке (`truncated_incomplete_tail_record`) и его безопасное отсечение.
    4. Карантин промежуточных поврежденных строк (`quarantined_N_malformed_records`).
    5. Обработка нулевых файлов и файлов с тотальным повреждением byte-0 (`byte_zero_corrupted_quarantine`) с инициализацией минимальной валидной структуры (`session_start` + `session_completed`).
    6. Принудительное добавление терминального маркера (`session_completed` / `turn_end`).
    7. Атомарная запись через временный файл с `fsync()` и `rename()`.
- **Программные критерии верификации**:
  - Обработка JSONL с оборванным хвостом генерирует действие `truncated_incomplete_tail_record` в `RepairReceipt.actions_applied`.
  - Передача пустого массива байт возвращает валидный JSONL с записями `session_start` и `session_completed`.
  - Каждый элемент результирующего потока десериализуется в `serde_json::Value::Object`.
  - Последняя запись восстановленного транскрипта всегда имеет поле `type: "session_completed"`.

---

### #35. Рассинхронизация порядковых номеров шагов (Ordinals) и регрессии последовательностей в мульти-агентных логах
- **Симптом разработчика и сценарий сбоя**:
  При возобновлении сессии после сбоя или слиянии параллельных веток субагентов в Codex/Claude транскриптах возникают дублирующиеся или регрессирующие номера шагов (`"ordinal": 6` следует за `"ordinal": 6`, либо `"ordinal": 4` после `"ordinal": 7`). В UI агента происходит зацикливание проекции состояния (state projection freeze), повтор одного и того же вызова инструмента или ошибка:
  `Error: Resumed session sequence regression: expected ordinal >= 12, received 8. State projection frozen.`
- **Затронутые среды агентов**: OpenAI Codex (`rollouts/**/*.jsonl`, `state_*.sqlite`), Claude Code, Cline.
- **Механизм ядра и системные вызовы**:
  - Сериализация порядковых номеров шагов (`ordinal: u64`) в JSONL и фиксация в таблицах SQLite (`next_rollout_ordinal`, `boundary_ordinal`).
  - Семантический анализатор (`SemanticDiagnostics`):
    - Проверка монотонности: `ordinal == previous` (`duplicate_ordinals`) и `ordinal < previous` (`regressed_ordinals`).
    - Проверка префиксов идентификаторов: `msg_`, `fc_`, `fco_`, `ctc_`, `ctco_`, `cmp_`.
    - Корреляция вызовов и ответов инструментов (`CallState`): сопоставление `call_id` с лимитом отслеживания `MAX_CORRELATION_STATES = 1024`.
  - Монотонный ре-секвенсор (`CodexAdapter::resequence_rollout_in_place`):
    - Построчная нормализация номеров `current_ordinal.saturating_add(1)` начиная с 0.
    - Дедупликация идентичных записей на границе возобновления (`deduplicated_ordinal_boundary_records`).
    - Обновление поля `ordinal` в JSON и синхронизация счетчика в SQLite индексе.
- **Программные критерии верификации**:
  - `duplicate_ordinals > 0` приводит к статусу `SessionHealth::Degraded` с описанием `duplicate ordinals in rollout`.
  - `regressed_ordinals > 0` генерирует предупреждение `regressed ordinals in rollout`.
  - После `resequence_rollout_in_place` все порядковые номера строго возрастают: `ord[i] == i` для `0 <= i < N`.
  - В отчете фиксируется действие `resequenced_monotonic_ordinals`.

---

### #36. Повреждение таблиц состояний Cursor SQLite (`state.vscdb`) и сбои парсинга усеченных JSON-значений в `ItemTable`
- **Симптом разработчика и сценарий сбоя**:
  При аварийном закрытии окон Cursor или сбоях фоновых расширений Composer база данных состояния рабочей области `state.vscdb` повреждается. Значения в таблице `ItemTable` по ключам `composer.composerData`, `workbench.panel.chatSidebar`, `interactive.sessions` оказываются усеченными или содержат невалидный JSON. При старте Cursor сбрасывает контекст диалога:
  `[Error] Unable to restore Composer session: JSON.parse error in state.vscdb (key: composer.composerData). Workspace chat reset.`
- **Затронутые среды агентов**: Cursor IDE (Composer, Chat, Multi-file edit modes).
- **Механизм ядра и системные вызовы**:
  - Файловая структура:
    - Linux: `~/.config/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb`
    - macOS: `~/Library/Application Support/Cursor/User/workspaceStorage/<workspace_id>/state.vscdb`
    - Windows: `%APPDATA%\Cursor\User\workspaceStorage\<workspace_id>\state.vscdb`
  - Таблица: SQLite v3, `ItemTable (key TEXT PRIMARY KEY, value TEXT)`.
  - Алгоритм ремонта (`CursorAdapter::repair_database_in_place`):
    1. Запрос строк `SELECT key, value FROM ItemTable`.
    2. Игнорирование учетных данных (`is_credential_key`: `token`, `auth`, `secret`, `apikey`, `password`).
    3. Восстановление синтаксиса JSON (`repair_json_string`): закрытие непарных кавычек, балансировка открывающих и закрывающих фигурных `{}` и квадратных `[]` скобок с учетом экранирования `\`.
    4. Обновление исправленных значений в `ItemTable`.
    5. Сброс WAL и проверка целостности через `SqliteWalManager::checkpoint_and_recover`.
- **Программные критерии верификации**:
  - Строка `{"nodes": [{"id": 1, "text": "val"` восстанавливается в `{"nodes": [{"id": 1, "text": "val"}]}`.
  - Ключи, содержащие подстроки `token`, `auth`, `apikey`, не подвергаются чтению или перезаписи.
  - `PRAGMA integrity_check` на базе после ремонта возвращает ровно одну строку `ok`.
  - Фиксация действий `repaired_item_table_key_<name>` и `checkpointed_and_verified_sqlite_wal` в `RepairReceipt`.

---

### #37. Осиротение дерева субагентов и фрагментация состояния при отсоединении родительского PID
- **Симптом разработчика и сценарий сбоя**:
  При аварийном завершении родительского процесса CLI-агента (`kill -9`, падение супервизора, закрытие вкладки терминала) дочерние процессы (субагенты, компиляторы, PTY-процессы bash, dev-серверы) становятся сиротами (orphaned), переподчиняются `init` (PID 1) и продолжают бесконтрольно исполняться на хосте, удерживая сетевые порты (3000, 8080) и повреждая рабочую копию.
- **Затронутые среды агентов**: Claude Code (fork processes, bash subshells), OpenHands, Aider, Cline.
- **Механизм ядра и системные вызовы**:
  - **Linux Parent-Death Signal**: `prctl(PR_SET_PDEATHSIG, SIGKILL)` в каждом дочернем процессе сразу после `fork()`, но до `execve()`. При исчезновении родительского потока ядро немедленно доставляет сигнал `SIGKILL` потомку.
  - **Linux PID Namespace Containment**: `clone(CLONE_NEWPID)` в FULL-тире песочницы. Процесс-инит внутри пространства имен перехватывает все сигналы и при своем завершении принудительно уничтожает всех потомков в пространстве через ядро.
  - **Process Group Cleanup**: Создание новой группы процессов через `setpgid(0, 0)` и отправка сигналов `killpg(pgrp, SIGTERM)` с последующим `killpg(pgrp, SIGKILL)` при завершении супервизора.
- **Программные критерии верификации**:
  - Наличие вызова `prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL)` во всех ветках создания дочерних процессов песочницы.
  - Наличие цикла `waitpid(-1, &mut status, libc::WNOHANG)` в PID-1 процессе песочницы.
  - Верификация отсутствия процессов в группе после завершения супервизора.

---

### #38. Утечка состояния между параллельными сессиями и загрязнение глобального хранилища метаданных
- **Симптом разработчика и сценарий сбоя**:
  При параллельной работе нескольких сессий агента в разных репозиториях они используют общий глобальный файл конфигурации и истории (`~/.claude.json`, `~/.codex/config.json`, глобальный `state.vscdb`). Происходит взаимная перезапись списков проектов `knownProjects`, подмена активных контекстов сессий и случайная утечка путей закрытых проектов в публичные отчеты.
- **Затронутые среды агентов**: Claude Code (`~/.claude.json`), Cursor IDE (`globalStorage/state.vscdb`), OpenAI Codex (`~/.codex/config.json`).
- **Механизм ядра и системные вызовы**:
  - Конкурентные неатомарные операции `read -> deserialize -> update -> write` без межпроцессных блокировок.
  - Изоляция окружения: подмена переменных `$HOME`, `$CLAUDE_HOME`, `$CODEX_HOME` на изолированные пути внутри песочницы.
  - Безопасная реконсиляция (`ClaudeAdapter::reconcile_projects`):
    - Валидация директорий `projects/<hash>` через `fs::read_dir` без перехода по симлинкам.
    - Атомарное обновление поля `knownProjects` в `~/.claude.json` с полным сохранением остальных полей и без затрагивания учетных записей (`is_credential_path`).
- **Программные критерии верификации**:
  - Пути, содержащие `credentials.json`, `auth.json`, `tokens.json`, `settings.json`, строго отклоняются функцией `is_credential_path`.
  - Сверка содержимого `.claude.json` до и после реконсиляции подтверждает сохранение всех пользовательских ключей, кроме `knownProjects`.
  - Запрет обработки директорий проектов, являющихся символическими ссылками.

---

### #39. Рассинхронизация указателей SQLite-индексов с файловой системой и появление фантомных сессий
- **Симптом разработчика и сценарий сбоя**:
  В Codex (`~/.codex/state_*.sqlite`, `logs_2.sqlite`) таблицы индексов содержат записи о сессиях (`rollout-*.jsonl`), которые были удалены, перемещены разработчиком или повреждены. При выполнении команд `vetto rescue scan` или попытке возобновления сессии агент падает:
  `vetto: error: session selector "rollout-2026-08-28T09-12-00.jsonl" is ambiguous or points to missing inode; provider index is out of sync with filesystem`.
- **Затронутые среды агентов**: OpenAI Codex (`state_*.sqlite`, `logs_2.sqlite`), Cursor IDE.
- **Механизм ядра и системные вызовы**:
  - Наличие записей в таблице сессий при возврате `ENOENT` от системных вызовов `stat()` / `fstatat()`.
  - Двухрежимный сканер сессий (`ScanDiscovery`):
    - `index-first`: чтение кандидатов из SQLite-индекса с ограничением выборки (`--limit`), проверкой существования файла на диске и валидацией через `safe_fs::validate_path`.
    - `filesystem-all` (`--all`): полный ограниченный рекурсивный обход файловой системы без использования устаревшего индекса SQLite.
    - Пометка отсутствующих или поврежденных сессий статусом `Availability::Unavailable` с указанием причины в `AdapterStatus.reason`.
- **Программные критерии верификации**:
  - Поддержка двух режимов `index-first` (по умолчанию с лимитом 50) и `filesystem-all` (при флаге `--all`).
  - Удаление файла сессии с диска при сохранении записи в SQLite приводит к корректному пропуску сессии без паники.
  - Функция `CodexAdapter::resolve_exact` возвращает сессию только при совпадении канонического пути и подтверждении регулярного файла.

---

### #40. Неатомарный откат состояний и состояние гонки при частичном восстановлении сессий
- **Симптом разработчика и сценарий сбоя**:
  Если утилита восстановления (`vetto rescue repair`) прерывается на середине операции записи (аварийное отключение питания, `SIGKILL`, переполнение диска), файл транскрипта остается частично перезаписанным и безвозвратно поврежденным. Исходная сессия теряется без возможности возврата к предыдущему состоянию.
- **Затронутые среды агентов**: Claude Code, OpenAI Codex, Cursor.
- **Механизм ядра и системные вызовы**:
  - Транзакционный бэкап:
    - До применения любых изменений создается резервная копия оригинального файла в каталоге `.vetto_backups/<timestamp>-<hash>/`.
    - Расчет исходного хеша `original_sha256 = SHA256(bytes)`.
  - Атомарная замена файла:
    - Запись отремонтированного содержимого во временный файл в том же каталоге (`safe_fs::atomic_write_file`).
    - Вызов `fsync()` на дескрипторе временного файла.
    - Атомарная замена через системный вызов `rename()` (POSIX) или `renameat2(RENAME_EXCHANGE)`.
  - Квитанция и откат (`RepairReceipt` / `rollback_repair`):
    - Генерация квитанции ремонта с путями, списком действий и хешами (`original_sha256`, `repaired_sha256`).
    - Команда `vetto rescue rollback` проверяет контрольную сумму бэкапа и атомарно восстанавливает исходный файл.
- **Программные критерии верификации**:
  - Генерация `RepairReceipt` содержит валидный путь `backup_archive_path`, который существует на диске.
  - Выполнение `rollback_repair` восстанавливает файл, чей `restored_sha256` строго совпадает с `original_sha256`.
  - Имитация сбоя до `fs::rename` оставляет исходный файл нетронутым.

---

## 5. Каталог требований: Трек R4 — Корпоративные политики, операционные гарды и регуляторный комплаенс

### #41. Семиуровневая иерархия политик и детерминированное наследование конфигураций безопасности
- **Симптом разработчика и сценарий сбоя**:
  В enterprise-инфраструктуре разработчик случайно переопределяет правила корпоративной безопасности локальным файлом `.vetto.override.toml` или CLI-флагом, либо локальная конфигурация репозитория не может переопределить профиль по умолчанию, вызывая ложные срабатывания блокировок при сборке проекта. Порядок применения настроек становится непредсказуемым.
- **Затронутые среды агентов**: Claude Code, Codex, Cursor, Aider, Cline, OpenHands.
- **Механизм ядра и системные вызовы**:
  - Строгая семиуровневая иерархия (`PolicySourceKind::precedence`):
    1. `Tier 1: SystemGlobal` (`/etc/vetto/policy.toml` или `%ProgramData%\vetto\policy.toml`) — наивысший институциональный приоритет.
    2. `Tier 2: UserGlobal` (`~/.config/vetto/policy.toml`) — пользовательские глобальные правила.
    3. `Tier 3: BuiltinProfile` (`default`, `strict`, `audit`, `permissive`) + наследование через `extends`.
    4. `Tier 4: AgentPreset` (`codex`, `claude`, `cursor`, `aider`, `cline`, `opencode`, `copilot`, `custom`).
    5. `Tier 5: Repository` (`.vetto/policy.toml`, `vetto.toml`) + фрагменты (`.vetto/policy.d/*.toml`).
    6. `Tier 6: LocalOverride` (`.vetto.override.toml`, `.vetto/local.toml`).
    7. `Tier 7: CliExplicit / CliOverride` (`--policy`, `--allow-write`, `--deny-read`).
  - Алгоритм детерминированного слияния:
    - Накопление прав на чтение и запись (`allow_read`, `allow_write`).
    - Абсолютный приоритет запрещающих правил (`deny_write`, `deny_read`, `deny_env`, `deny_network`), вычитаемых из любого белого списка.
    - Слияние лимитов ресурсов по самому строгому значению (`ResourceLimits::merge_strictest`).
- **Программные критерии верификации**:
  - Значения `PolicySourceKind::precedence()` строго монотонны от 1 до 7.
  - Все структуры десериализации содержат `#[serde(deny_unknown_fields)]`.
  - Тест 7-слойного наложения проверяет, что `deny_write` из Tier 1 невозможно отменить через `allow_write` в Tier 7.

---

### #42. Корпоративная блокировка политик (Enterprise Lockdown) и иммутабельные директивы безопасности
- **Симптом разработчика и сценарий сбоя**:
  Разработчик или вредоносный скрипт в репозитории добавляет в локальный `.vetto/policy.toml` директиву `allow_write = ["/etc", "/var/run"]` или передает CLI-параметр `--allow-write /`, пытаясь отключить изоляцию и получить доступ к хостовой системе. В незащищенных конфигурациях это приводит к полной компрометации хоста.
- **Затронутые среды агентов**: Все агенты в корпоративных CI/CD раннерах и рабочих станциях.
- **Механизм ядра и системные вызовы**:
  - Установка секции `[security] immutable = true` в системной политике `SystemGlobal` (Tier 1).
  - Fail-Closed Валидация (`checker::validate_lockdown`):
    - При активном `is_immutable` загрузчик политик проверяет все нижележащие слои (Tier 2–7).
    - Любая попытка добавить путь записи/чтения, перекрывающий системный `deny`, расширить сетевые правила (`allow`), удалить запрещенные переменные окружения или увеличить лимиты ресурсов немедленно прерывает выполнение до старта агента.
    - Генерация фатальной ошибки `VettoError::PolicyLockdownViolation`.
- **Программные критерии верификации**:
  - Попытка переопределения запрещенного пути при `immutable = true` выбрасывает `PolicyLockdownViolation`.
  - В коде отсутствует возможность игнорирования или подавления ошибки `PolicyLockdownViolation`.
  - Поле `immutable: bool` парсится только из доверенного Tier 1 источника.

---

### #43. Субтрактивные запрещающие правила (Subtractive Deny) поверх позитивных Landlock Allowlists
- **Симптом разработчика и сценарий сбоя**:
  Landlock в ядре Linux работает по модели чистого белого списка (positive allowlist). При предоставлении агенту доступа к директории проекта `$PROJECT` агент автоматически получает доступ к файлам `.env`, `.git/config`, `id_rsa`, находящимся внутри проекта. Традиционные песочницы не могут запретить чтение отдельного файла внутри разрешенного дерева каталогов.
- **Затронутые среды агентов**: Все агенты на Linux (Landlock ABI v1–v6).
- **Механизм ядра и системные вызовы**:
  - **Linux FULL Tier (Landlock + User/Mount Namespaces)**:
    - Создание пространства монтирования (`CLONE_NEWNS | CLONE_NEWUSER`).
    - Маскирование секретных файлов: `mount("/dev/null", target_path, NULL, MS_BIND, NULL)` поверх каждого файла из `deny_read` / `deny_write`.
    - Маскирование секретных директорий: монтирование пустого `tmpfs` с правами `0000` поверх запрещенных каталогов (`.git`, `.ssh`).
    - Наложение правил Landlock поверх модифицированного дерева монтирования.
  - **Linux FS-ONLY Tier (Landlock без namespaces)**:
    - Рекурсивный обход дерева каталогов с лимитом `FS_ONLY_ENUMERATION_BUDGET = 20_000` записей.
    - Построение точечного списка путей, исключающего запрещенные файлы и шаблоны.
    - При превышении бюджета обхода — аварийная остановка (fail-closed).
- **Программные критерии верификации**:
  - Проверка вызовов маскирования файлов на `/dev/null` и директорий на пустой `tmpfs` в FULL тире.
  - Превышение лимита в 20 000 записей возвращает ошибку компиляции правил Landlock.
  - Попытка чтения маскированного файла `.env` возвращает 0 байт (EOF) или `EACCES`.

---

### #44. Криптографический аудит с цепочечным хешированием журналов (SHA-256 HMAC Chained Logging)
- **Симптом разработчика и сценарий сбоя**:
  Скомпрометированный агент или вредоносный скрипт пытается модифицировать, усечь или удалить строки в локальном лог-файле аудита (`vetto.jsonl`), чтобы скрыть факт чтения приватных ключей или обращения к недоверенным внешним серверам.
- **Затронутые среды агентов**: Все агенты при проведении аудита безопасности и compliance-проверок.
- **Механизм ядра и системные вызовы**:
  - Защищенный I/O sink (`open_append_nofollow`):
    - Открытие файла журнала через дескриптор каталога с флагами `O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK`.
    - Проверка через `fstat`, что открытый дескриптор является регулярным файлом с числом ссылок `nlink == 1`.
  - Криптографическая цепочка (HMAC Chaining):
    - Каждая строка события содержит: `seq_num`, `timestamp_ns`, `event_payload`, `prev_hash`, `hmac_signature`.
    - Формула связывания: $H_n = \text{HMAC-SHA256}(K_{\text{session}}, H_{n-1} \parallel \text{seq\_num} \parallel \text{payload}_n)$.
    - Любое удаление или модификация строки делает цепочку невалидной при проверке `vetto audit verify`.
- **Программные критерии верификации**:
  - Попытка направить лог-файл через символическую ссылку отклоняется с `PermissionDenied`.
  - Валидация последовательности $H_n$ от начального seed-хеша до последней записи.
  - Модификация одного байта в середине JSONL-файла приводит к отказу верификации с указанием номера поврежденной строки.

---

### #45. Экспорт телеметрии песочницы в формат SARIF 2.1.0 для интеграции с enterprise CI/CD
- **Симптом разработчика и сценарий сбоя**:
  При выполнении задач агентом в CI/CD пайплайнах (GitHub Actions, GitLab CI) заблокированные попытки несанкционированного доступа к файлам и сети теряются в неструктурированных текстовых логах консоли, не попадая во встроенные панели безопасности (GitHub Security Dashboard / Code Scanning).
- **Затронутые среды агентов**: CI/CD раннеры, headless-агенты (Claude Code CI, Codex CI, OpenHands).
- **Механизм ядра и системные вызовы**:
  - Сбор событий ядра: агрегация заблокированных системных вызовов Landlock, Seccomp BPF и брокера сети в структуру `SessionStats`.
  - SARIF 2.1.0 Рендерер (`src/report/sarif.rs`):
    - Соответствие схеме `https://json.schemastore.org/sarif-2.1.0.json`.
    - Стандартизированные правила:
      - `vetto.blocked-attempt` (уровень `error`) — блокировка доступа к файловой системе.
      - `vetto.network-denied` (уровень `error`) — блокировка сетевого подключения CONNECT.
      - `vetto.suspicious-signal` (уровень `warning` / `note`) — эвристические паттерны подозрительной активности.
    - Физические локации артефактов (`artifactLocation.uri`) и метаданные процесса (`properties.process`, `properties.source`).
- **Программные критерии верификации**:
  - Сгенерированный JSON успешно проходит валидацию схемы SARIF 2.1.0.
  - В выводе присутствуют обязательные идентификаторы правил `vetto.blocked-attempt` и `vetto.network-denied`.
  - Все текстовые поля экранируются от управляющих символов функцией `report::clean`.

---

### #46. Регуляторное требование Zero-Daemon: отсутствие фоновых служб и эфемерный жизненный цикл процессов
- **Симптом разработчика и сценарий сбоя**:
  Использование Docker, Podman или фоновых демонов для изоляции агентов создает риски эскалации привилегий через daemon-сокеты (`/var/run/docker.sock`), оставляет зависшие контейнеры при сбоях раннера и нарушает требования регуляторов к отсутствию root-демонов в среде разработки.
- **Затронутые среды агентов**: Все поддерживаемые агенты.
- **Механизм ядра и системные вызовы**:
  - Zero-Daemon Архитектура: полный отказ от демонов, сервисов и фоновых сокетов. Один вызов бинарника `vetto` владеет ровно одной сессией.
  - Строгий порядок запуска (Startup Ordering):
    1. Однопоточный парсинг политик, резолв путей и подготовка дескрипторов PTY/сокетов.
    2. Префлайт-проверка возможностей ядра (Landlock, seccomp).
    3. `fork()` -> установка `PR_SET_NO_NEW_PRIVS` -> активация Landlock/Seccomp -> `execve()`.
    4. Создание наблюдающих потоков только ПОСЛЕ успешного старта песочницы.
  - Гарантированная зачистка: завершение супервизора автоматически уничтожает всё дерево процессов агента без остаточных процессов.
- **Программные критерии верификации**:
  - В кодовой базе отсутствуют вызовы `daemon(3)`, создание фоновых detached-сервисов или привязка к постоянным daemon-сокетам.
  - Проверка того, что создание песочницы и установка ограничений происходят до инициализации пула потоков Tokio/Rayon.
  - Завершение супервизора не оставляет активных процессов в таблице процессов ОС.

---

### #47. Регуляторное соответствие Zero-Telemetry: полная изоляция в закрытых (Air-Gapped) контурах
- **Симптом разработчика и сценарий сбоя**:
  Сторонние AI-утилиты и песочницы скрытно отправляют телеметрию (OpenTelemetry, PostHog, Sentry, Segment) на внешние серверы аналитики, что приводит к утечке исходного кода и метаданных в закрытых банковских, оборонных и корпоративных контурах.
- **Затронутые среды агентов**: Все агенты в закрытых, изолированных (air-gapped) и регулируемых средах.
- **Механизм ядра и системные вызовы**:
  - Сетевая изоляция (`network = "off"`):
    - Linux FULL: создание изолированного пространства имен сети `CLONE_NEWNET` без создания виртуальных интерфейсов.
    - Linux FS-ONLY: Seccomp BPF блокирует системный вызов `socket(AF_INET, ...)` и `socket(AF_INET6, ...)` с кодом ошибки `EPERM`.
  - Строгий Zero-Telemetry в бинарнике:
    - Полное отсутствие в коде зависимостей сетевых аналитических библиотек.
    - Запрет неявных фоновых DNS-запросов и проверок обновлений.
    - Формирование всех отчетов строго локально в директории `.vetto/reports`.
- **Программные критерии верификации**:
  - Отсутствие в дереве зависимостей (`Cargo.lock`) и исходном коде пакетов телеметрии и аналитики.
  - В режиме `network = "off"` вызов `socket(AF_INET)` возвращает `EPERM`.
  - Все отчеты записываются через `ReportStorage` исключительно в локальную файловую систему.

---

### #48. Динамическая контекстная оценка политик и строгие лимиты условий (Conditional Budgets)
- **Симптом разработчика и сценарий сбоя**:
  Статические политики безопасности не могут учитывать контекст ветки Git или специфику проекта (например, строгий профиль для `main`/`release`, но расширенный для `feature/*`), а неконтролируемые условия TOML приводят к зависанию загрузчика из-за бесконечных поисков файлов по глубоким деревьям каталогов.
- **Затронутые среды агентов**: Все агенты в мульти-репозиторных и монорепозиторных проектах.
- **Механизм ядра и системные вызовы**:
  - AST Движок условий (`src/policy/conditions.rs`):
    - `branch`: сопоставление имени текущей ветки Git по glob-шаблонам.
    - `file_exists`: проверка наличия файлов-маркеров в корне проекта.
    - `project_contains`: поиск строковых маркеров в файлах проекта.
  - Строгие лимиты бюджетов сканирования (`ConditionContext`):
    - `max_depth = 4` — ограничение глубины обхода директорий.
    - `max_files = 1000` — лимит проверенных файлов.
    - `max_scan_bytes = 1048576` (1 МБ) — максимальный объем прочитанных байт при поиске содержимого.
    - Превышение лимита приводит к безопасному отказу правила (fail-closed).
- **Программные критерии верификации**:
  - Превышение лимита `max_files` или `max_scan_bytes` останавливает сканирование без паники и не активирует рискованное правило.
  - Проверка корректной активации условий для веток `main`, `feature/*`, `release/v*`.
  - Сканер условий игнорирует символические ссылки при обходе дерева файлов.

---

### #49. Изоляция параллельных агентов и предотвращение горизонтального перемещения (Lateral Movement)
- **Симптом разработчика и сценарий сбоя**:
  При одновременном запуске нескольких независимых агентов в одной системе (например, воркер A тестирует непроверенный код из PR, воркер B работает с production-конфигурацией) скомпрометированный агент A может через общую память `/dev/shm`, абстрактные Unix-сокеты или `localhost` атаковать агента B.
- **Затронутые среды агентов**: Мульти-агентные группы (Claude Code swarms, OpenHands, Codex multi-agent).
- **Механизм ядра и системные вызовы**:
  - Комплексная изоляция пространств имен (`src/multi/isolation.rs`):
    - Индивидуальный IPC namespace (`CLONE_NEWIPC`) для каждого агента.
    - Приватный `/dev/shm` ограниченного размера (`mount -t tmpfs -o size=64M,noexec,nosuid,nodev`).
    - Приватный Network namespace (`CLONE_NEWNET`) с индивидуальным bridge-сокетом.
    - Изоляция `/proc` и PID namespace (`CLONE_NEWPID`).
  - Seccomp Фильтрация:
    - Запрет абстрактных Unix-сокетов (проверка первого байта `sun_path[0] == 0` -> блокировка).
    - Блокировка системных вызовов инспекции процессов: `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`.
- **Программные критерии верификации**:
  - Создание очереди сообщений или сегмента разделяемой памяти в агенте A невидимо для агента B.
  - Попытка привязки (bind) к абстрактному сокету возвращает `EPERM`.
  - Попытка вызова `ptrace(PTRACE_ATTACH, ...)` на процесс соседнего агента немедленно блокируется ядром.

---

### #50. Многостадийная очистка секретов и фильтрация токенов высокой энтропии (Secret Scrubbing Pipeline)
- **Симптом разработчика и сценарий сбоя**:
  Агенты в процессе генерации кода, логов и отчетов случайно выводят приватные ключи SSH/TLS, токены доступа GitHub/AWS/OpenAI или пароли из `.env` файлов в стандартный вывод (PTY), отчеты и JSONL-логи, что приводит к компрометации учетных записей при экспорте логов в CI/CD.
- **Затронутые среды агентов**: Все поддерживаемые агенты (терминальный вывод PTY, логи `--jsonl`, HTML/SARIF отчеты).
- **Механизм ядра и системные вызовы**:
  - Многостадийный потоковый конвейер (`sanitizer.rs` / `pty/entropy.rs`):
    1. `redact_pem`: Поиск блоков `-----BEGIN ...` и замена тела ключа на `[REDACTED PEM BODY]`.
    2. `redact_prefixed_tokens`: Детектирование префиксов с минимальной длиной:
       - AWS: `AKIA` (16), `ASIA` (16)
       - GitHub: `ghp_` (20), `gho_` (20), `ghu_` (20), `ghs_` (20), `ghr_` (20)
       - OpenAI/Anthropic: `sk-` (24)
       - Slack: `xoxb-` (20), `xoxp-` (20), `xoxa-` (20), `xoxs-` (20)
    3. `redact_bearer_tokens`: Маскирование токенов в заголовках `Authorization: Bearer <token>`.
    4. `redact_env_assignments`: Маскирование присваиваний переменных с ключевыми словами `KEY=`, `SECRET=`, `TOKEN=`, `PASSWORD=`.
    5. `redact_high_entropy_runs`: Расчет энтропии Шеннона ($H \ge 3.8$) на скользящем окне для выявления произвольных hex/base64 секретов длиной от 24 символов с заменой на `[REDACTED HIGH-ENTROPY TOKEN]`.
  - Сохранение UTF-8: Обработка только ASCII-границ, исключающая повреждение многобайтовых символов UTF-8.
- **Программные критерии верификации**:
  - Токены `AKIAIOSFODNN7EXAMPLE` и `ghp_1234567890abcdefghijklmnopqrstuvwxyz` заменяются на `[REDACTED]`.
  - Блок приватного ключа RSA/ECDSA маскируется с сохранением заголовков.
  - Шестнадцатеричный токен случайных байт длиной 32 символа маскируется фильтром энтропии.
  - Текст на русском языке и эмодзи не повреждаются при прохождении через санатор.

---

## 6. Кроссплатформенная сравнительная матрица архитектурных механизмов

Ниже представлена детальная инженерная матрица эквивалентности примитивов изоляции ядра, системных вызовов и отказоустойчивых механизмов между Linux, macOS и Windows.

| Архитектурный домен / Вектор | Linux (FULL / FS-ONLY) | macOS (Darwin 22+) | Windows (NT 10.0+ / Server 2022) |
|---|---|---|---|
| **Изоляция файловой системы (Positive)** | Landlock LSM ABI v1–v6 (`SYS_landlock_create_ruleset`, `SYS_landlock_add_rule`) | Seatbelt SBPL Profiles (`sandbox_init_with_parameters` in memory) | AppContainer Isolation (`CreateAppContainerProfile`, `UpdateProcThreadAttribute`) |
| **Субтрактивное маскирование секретов** | Mount namespace + `/dev/null` bind-mount / empty `tmpfs` | Trailing `(deny file-read*)` in SBPL («последнее совпадение побеждает») | Canonical DACL with preceding `DENY_ACCESS` ACEs |
| **Сетевые ворота и порты (TCP)** | Landlock ABI v4 (`BIND_TCP`, `CONNECT_TCP`) + Seccomp BPF | Seatbelt SBPL `(deny network*)` / `(allow network-outbound)` | Windows Filtering Platform (WFP) / AppContainer Network Capabilities |
| **Mach / IPC / D-Bus Gates** | Abstract socket scope ban (ABI v6) + `CLONE_NEWIPC` | Mach lookup filtering (`(allow mach-lookup "com.apple.trustd.agent")`) | Named Pipe DACL & Low-Integrity Object Security Descriptor |
| **Блокировка побегов ядра / Syscalls** | Seccomp-BPF whitelist with `EPERM` (28 escape syscalls) | Endpoint Security AUTH hooks (`es_respond_auth_result`) | Restricted Token (`DISABLE_MAX_PRIVILEGE`, `LUA_TOKEN`) |
| **Дерево процессов и предотвращение сирот** | `prctl(PR_SET_PDEATHSIG, SIGKILL)` + `CLONE_NEWPID` | Process Group `killpg(pgrp, SIGKILL)` on supervisor drop | Job Objects (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no breakaway) |
| **Контроль ресурсов и DoS** | `setrlimit` (RLIMIT_AS, RLIMIT_NPROC) + Cgroup v2 | `setrlimit` (Darwin POSIX) | `SetInformationJobObject` (JobObjectExtendedLimitInformation) |
| **Стриминговая маскировка PTY** | Aho-Corasick + Shannon Entropy in `termios` raw pump | Aho-Corasick + Shannon Entropy in `termios` raw pump | Windows ConPTY Stream Scrubbing Filter |
| **Межпроцессные блокировки сессий** | Linux Open File Description Locks (`fcntl(F_OFD_SETLK)`) | BSD File Locks (`flock(LOCK_EX \| LOCK_NB)`) | Win32 File Locking (`LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)`) |
| **Восстановление баз SQLite** | `SqliteWalManager`: staging copy + `wal_checkpoint(TRUNCATE)` | `SqliteWalManager`: staging copy + `wal_checkpoint(TRUNCATE)` | `SqliteWalManager`: staging copy + `wal_checkpoint(TRUNCATE)` |
| **Защита от DNS Rebinding** | Broker single-resolve & CIDR Blacklist validation | Broker single-resolve & CIDR Blacklist validation | Broker single-resolve & CIDR Blacklist validation |
| **Криптографический аудит** | HMAC-SHA256 Chained Event Log (`O_APPEND \| O_NOFOLLOW`) | HMAC-SHA256 Chained Event Log (`O_APPEND \| O_NOFOLLOW`) | HMAC-SHA256 Chained Event Log (`FILE_APPEND_DATA`) |

---

## 7. Конечные автоматы восстановления после сбоев (Failure Recovery State Machines)

### 7.1. Автомат захвата блокировки сессии и обнаружения брошенных процессов (Session Lock State Machine)

```
       +-----------------------+
       |   Начало захвата      |
       +-----------+-----------+
                   |
                   v
       +-----------------------+      Успех
       |   OFD fcntl(F_WRLCK)  +-------------------------> [ ЗАХВАЧЕНО ]
       +-----------+-----------+                         (SessionLockGuard)
                   | Ошибка EACCES / EAGAIN
                   v
       +-----------------------+
       | Чтение lock-файла:    |
       | PID, acquired_at, ttl |
       +-----------+-----------+
                   |
                   v
       +-----------------------+      ESRCH (Процесс мертв)
       |   Liveness Probe:     +-------------------------> [ ПЕРЕХВАТ СТАРОГО LOCK ]
       |     kill(PID, 0)      |                                    |
       +-----------+-----------+                                    |
                   | Успех (Процесс жив)                            |
                   v                                                |
       +-----------------------+                                    |
       |  Проверка таймаута:   |                                    |
       | now > acquired + ttl? |                                    |
       +-----+-----------+-----+                                    |
             |           |                                          |
        Да   |           | Нет (Активный процесс)                   |
             |           v                                          |
             |     [ ОШИБКА КОНКУРЕНЦИИ ]                           |
             |     (-32600 active writer)                           |
             v                                                      v
       +------------------------------------------------------------+
       | Атомарная перезапись lock-файла новым PID и захват OFD lock|
       +-----------------------------+------------------------------+
                                     |
                                     v
                             [ ЗАХВАЧЕНО ]
```

### 7.2. Автомат двухфазного восстановления SQLite WAL на VFS-трансляторах (SQLite WAL Staging State Machine)

```
       +---------------------------------------+
       | Обнаружен SQLite WAL / Malformed файл |
       +-------------------+-------------------+
                           |
                           v
       +---------------------------------------+
       |  Проверка символических ссылок        |
       |  (is_symlink == true -> Ошибка)       |
       +-------------------+-------------------+
                           | Регулярные файлы
                           v
       +---------------------------------------+
       | Создание приватного staging каталога  |
       | на локальной FS (tmpfs / ext4)        |
       +-------------------+-------------------+
                           |
                           v
       +---------------------------------------+
       | Копирование base.sqlite, -wal, -shm   |
       +-------------------+-------------------+
                           |
                           v
       +---------------------------------------+
       | Открытие в staging:                   |
       | PRAGMA busy_timeout = 5000;           |
       | PRAGMA wal_checkpoint(TRUNCATE);      |
       +-------------------+-------------------+
                           |
                           v
       +---------------------------------------+
       | PRAGMA integrity_check(100);          |
       +-----+---------------------------+-----+
             |                           |
        Результат "ok"                   | Ошибка повреждения
             v                           v
       +-------------------+     +----------------------------------+
       | Атомарная замена  |     | Изоляция в карантин:             |
       | исходного файла   |     | .vetto_quarantine/<hash>.corrupt |
       | через fsync+rename|     +----------------------------------+
       +---------+---------+
                 |
                 v
       [ БАЗА ВОССТАНОВЛЕНА ]
```

### 7.3. Автомат компактизации потока JSONL и отсечения неполных токенов (JSONL Compaction State Machine)

```
       +------------------------------------------------+
       |  Чтение байтового потока транскрипта сессии   |
       +-----------------------+------------------------+
                               |
                               v
       +------------------------------------------------+
       |  Разделение по байтам '\n', удаление '\r'      |
       +-----------------------+------------------------+
                               |
                               v
             +-----------------+-----------------+
             | Для каждой строки i от 0 до N:    |
             +-----------------+-----------------+
                               |
                               v
       +------------------------------------------------+
       |  serde_json::from_slice::<Value>(&line[i])     |
       +-----+------------------------------------+-----+
             |                                    |
        Успешный JSON                             | Ошибка синтаксиса
             v                                    v
       +----------------------+         +----------------------+
       | Добавление в буфер   |         | Это последняя строка |
       | валидных записей     |         | i == N (хвост файла)?|
       +----------------------+         +---+--------------+---+
                                            |              |
                                       Да   |              | Нет (внутренняя строка)
                                            v              v
       +------------------------------------+---+    +----------------------+
       | Действие:                              |    | Действие:            |
       | truncated_incomplete_tail_record       |    | quarantined_record   |
       +--------------------+-------------------+    +----------------------+
                            |
                            v
       +------------------------------------------------+
       | Проверка терминального маркера:                |
       | Если last.type != "session_completed" ->       |
       | инъекция завершающей записи                    |
       +--------------------+---------------------------+
                            |
                            v
       +------------------------------------------------+
       | Атомарная запись в целевой файл через tmp+fsync|
       +--------------------+---------------------------+
                            |
                            v
               [ ТРАНСКРИПТ ВОССТАНОВЛЕН ]
```

### 7.4. Автомат 7-уровневого детерминированного слияния политик (Policy Merge & Lockdown State Machine)

```
       +------------------------------------------------+
       | Инициализация пустого контекста безопасности   |
       +-----------------------+------------------------+
                               |
                               v
       +------------------------------------------------+
       | Загрузка Tier 1: SystemGlobal (/etc/vetto/...) |
       +-----------------------+------------------------+
                               |
                               v
       +------------------------------------------------+
       | Проверка: установлен ли immutable = true?      |
       +-----+------------------------------------+-----+
             |                                    |
        Да (Enterprise Lockdown)                  | Нет (Стандартный режим)
             v                                    v
       +-----------------------------+    +-----------------------------+
       | Валидация Tier 2..7:        |    | Последовательное слияние    |
       | Запрет расширения allow     |    | Tier 2..7 с накоплением     |
       | Запрет переопределения deny |    | allow и вычитанием deny     |
       | Запрет повышения лимитов    |    +--------------+--------------+
       +-------------+---------------+                   |
                     |                                   |
         Нарушение   |   Все правила валидны             |
         v           v                                   |
    [ ОШИБКА:        +-----------------------------------+
    PolicyLockdown   |
    Violation ]      v
       +------------------------------------------------+
       | Формирование результирующего набора правил:    |
       | EffectiveAllow = (Union Allow) - (Union Deny)  |
       | StrictestLimits = Min(Limits)                  |
       +-----------------------+------------------------+
                               |
                               v
       [ РЕЗУЛЬТИРУЮЩАЯ ПОЛИТИКА ГОТОВА К ИСПОЛНЕНИЮ ]
```

---

## 8. Сводная матрица всех 50 требований каталога

| ID | Трек | Название требования | Затронутые агенты | Ключевые механизмы ОС | Программный критерий верификации |
|---|---|---|---|---|---|
| **R1-01** | R1 Kernel | Landlock ABI v1–v3 FS Access | Claude, Codex, Cursor, Aider, Cline, OpenHands | `SYS_landlock_create_ruleset`, `LANDLOCK_ACCESS_FS_*` | Ruleset attr size 8 байт, REFER/TRUNCATE маски |
| **R1-02** | R1 Kernel | Landlock ABI v4 TCP Sandboxing | Claude, Codex, Cursor, OpenHands | `LANDLOCK_ACCESS_NET_BIND_TCP`, `CONNECT_TCP` | Ruleset attr size 16 байт, `LandlockNetPortAttr` 16 байт |
| **R1-03** | R1 Kernel | Landlock ABI v5 PTY Ioctl Control | Claude, Cursor, Aider, OpenHands | `LANDLOCK_ACCESS_FS_IOCTL_DEV`, `/dev/pts`, `/dev/ptmx` | Валидация прав `IOCTL_DEV` на символьные устройства |
| **R1-04** | R1 Kernel | Landlock ABI v6 Scope Isolation | Claude, Codex, Cursor, OpenHands | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `SIGNAL` | Ruleset attr size 24 байт, блокировка префикса `@` |
| **R1-05** | R1 Kernel | Seccomp-BPF User Notification Tap | Claude, Codex, Cursor, Aider, Cline, OpenHands | `SECCOMP_RET_USER_NOTIF`, `SECCOMP_IOCTL_NOTIF_RECV` | Проверка флага `CONTINUE` и опкода `0x7fc00000` |
| **R1-06** | R1 Kernel | Seccomp ADDFD `/dev/null` Injection | Claude, Codex, Cursor, OpenHands | `SECCOMP_IOCTL_NOTIF_ADDFD`, whitelist системных путей | Запрет инъекции на `execve`/`unlink`, источник `/dev/null` |
| **R1-07** | R1 Kernel | Seccomp 28 Syscall Escape Hardening | Claude, Codex, Cursor, Aider, Cline, OpenHands | `prctl(PR_SET_SECCOMP)`, блокировка `mount`, `ptrace`, `bpf` | BPF возврат `EPERM` для 28 вызовов, kill на x32 |
| **R1-08** | R1 Kernel | Unprivileged Userns 2-Pipe Handshake | Claude, Codex, Cursor, OpenHands | `unshare(CLONE_NEWUSER)`, `uid_map`, `gid_map`, 2 pipes | Закрытие дескрипторов в потомке/родителе, preflight check |
| **R1-09** | R1 Kernel | Mount Namespace `/dev/shm` & `/tmp` | Claude, Codex, Cursor, Aider, Cline, OpenHands | `CLONE_NEWNS`, `MS_PRIVATE`, 64MB `tmpfs` mounts | Лимиты 64 МБ, bind-mount `/dev/null` для файлов |
| **R1-10** | R1 Kernel | PID Namespace `hidepid=2` `/proc` | Claude, Codex, Cursor, OpenHands | `CLONE_NEWPID`, `mount("proc", "hidepid=2")` | Обработка `ProcVisibility::Fallback` при `EINVAL` |
| **R1-11** | R1 Kernel | Process & IPC Resource Ceilings | Claude, Codex, Cursor, Aider, Cline, OpenHands | `setrlimit` (RLIMIT_AS, RLIMIT_NPROC, RLIMIT_MSGQUEUE) | Равенство `rlim_cur == rlim_max`, предотвращение DoS |
| **R1-12** | R1 Kernel | macOS Seatbelt SBPL Profiles | Claude, Cursor, Codex, Aider, Cline | `sandbox_init_with_parameters`, trailing `(deny)` | Проверка генератора параметров `ALLOW_*`, `DENY_*` |
| **R1-13** | R1 Kernel | macOS Endpoint Security AUTH Gates | Claude, Cursor, OpenHands | `es_new_client`, `ES_EVENT_TYPE_AUTH_*` | Проверка root/entitlement, честный fallback на Seatbelt |
| **R1-14** | R1 Kernel | Windows AppContainer Canonical DACL | Claude, Codex, Cursor, Cline | `CreateAppContainerProfile`, `SetEntriesInAclW` | Порядок ACE (Deny перед Grant), размер `SidAndAttributes` |
| **R1-15** | R1 Kernel | Windows Job Objects & Low-Integrity | Claude, Codex, Cursor, Aider, OpenHands | `CreateJobObjectW`, `KILL_ON_JOB_CLOSE`, Low-RID | Запрет Breakaway, токен `DISABLE_MAX_PRIVILEGE` |
| **R2-01** | R2 Toolchain | Go TLS & `trustd.agent` Mach Gates | Claude, Cursor, Aider, OpenHands | macOS Mach IPC `bootstrap_look_up`, `SSL_CERT_FILE` | Наличие Mach-lookup директивы для `trustd.agent` в SBPL |
| **R2-02** | R2 Toolchain | Git over SSH (Port 22) Proxy Broker | Claude, Codex, Cursor, Aider, Cline, OpenHands | `AF_UNIX` сокет, `ProxyCommand`, SSH opaque pump | Валидация `github.com:22`, отказ на не-22 портах |
| **R2-03** | R2 Toolchain | Subshell `$()` & Recursion Barrier | Claude, Codex, Cursor, Aider, OpenHands | `pipe2`, `fork`, `execve`, `VETTO_SANDBOXED=1` | Проверка флагов рекурсии, исключение каталога shims |
| **R2-04** | R2 Toolchain | PTY Aho-Corasick Secret Redaction | Claude, Cursor, Aider, OpenHands | `termios`, Aho-Corasick DFA, 256-byte carry buffer | `output.len() == secret.len()` (PadMask preservation) |
| **R2-05** | R2 Toolchain | Shannon Entropy Secret Filtering | Claude, Codex, Cursor, Aider, Cline, OpenHands | Энтропия Шеннона ($H > 4.5$), hex/UUID whitelist | Игнорирование SHA-1/UUID, маскирование токенов |
| **R2-06** | R2 Toolchain | IDE Statusline PTY & `SIGWINCH` | Cursor, Claude Code, Cline | `ioctl(TIOCSWINSZ)`, `SIGWINCH`, `cfmakeraw` | Резервирование строки `ws_row - 1`, хоткей `0x1D` |
| **R2-07** | R2 Toolchain | Node.js npm/npx Cache Isolation | Claude, Codex, Cursor, Aider, Cline, OpenHands | `npm_config_cache`, `NPM_CONFIG_CACHE` | Валидация профилей агентов на переопределение кэша |
| **R2-08** | R2 Toolchain | Rust Cargo Multi-Tenancy & Locks | Claude, Codex, Cursor, Aider, OpenHands | `fcntl(F_SETLK)`, `CARGO_HOME`, `CARGO_TARGET_DIR` | Read-only реестр, изолированный target проекта |
| **R2-09** | R2 Toolchain | Python Wheel Isolation & `EXDEV` | Claude, Codex, Cursor, Aider, OpenHands | `UV_LINK_MODE=copy`, `PIP_CACHE_DIR` | Предотвращение ошибок `EXDEV` при создании жестких ссылок |
| **R2-10** | R2 Toolchain | pnpm CAS Store & Mount Crossings | Claude, Cursor, OpenHands | `linkat`, `package-import-method=copy` | Право `LANDLOCK_ACCESS_FS_REFER`, fallback на copy |
| **R2-11** | R2 Toolchain | Bun SQLite WAL Cache Isolation | Claude, Cursor, OpenHands | `BUN_INSTALL_CACHE_DIR`, SQLite WAL shared memory | Изоляция кэша Bun и временных сокетов |
| **R2-12** | R2 Toolchain | DebugPortGuard (9222, 9229, 5678) | Claude, Codex, Cursor, OpenHands | Перехват loopback, токен `X-Vetto-Debug-Token` | Блокировка 9222/9229/5678 без токена (`403 Forbidden`) |
| **R2-13** | R2 Toolchain | DNS Rebinding Pinning & Cloud CIDRs | Claude, Codex, Cursor, OpenHands | `getaddrinfo`, IP blacklist (`169.254/16`, `127/8`) | Отклонение метаданных AWS, DNS pinning на сессию |
| **R2-14** | R2 Toolchain | FS-ONLY Process Death & Cleanup | Claude, Codex, Cursor, Aider, Cline, OpenHands | `prctl(PR_SET_PDEATHSIG, SIGKILL)`, `setpgid` | Проверка `getppid()`, зачистка группы процессов `killpg` |
| **R2-15** | R2 Toolchain | Multi-Arch Syscall Translation | Claude, Codex, Cursor, Aider, Cline, OpenHands | `libc::SYS_*`, `native_audit_arch()` BPF check | Защита от смешения x86_64/aarch64 номеров системных вызовов |
| **R3-01** | R3 State | OFD Locks & Zombie Concurrency | Claude, Codex, Aider, OpenHands, Cline | `fcntl(F_OFD_SETLK)`, `kill(pid, 0)` liveness probe | Перехват stale lock при мертвом PID, RAII drop |
| **R3-02** | R3 State | Cross-VFS SQLite WAL Timeouts (9P) | Codex, Cursor, Cline, OpenHands | SQLite staging copy, `PRAGMA wal_checkpoint(TRUNCATE)` | Запрет прямых запросов к VFS, `integrity_check == ok` |
| **R3-03** | R3 State | Subagent Fork Base64 History Bloat | Claude, OpenHands, Cline, Aider | `safe_fs::read_bounded`, лимит 512MB на сессию | Ошибка при превышении 512 МБ, проверка SHA-256 |
| **R3-04** | R3 State | Corrupted JSONL Tail Compaction | Claude, Codex, Cline, OpenHands | Парсинг JSONL, отсечение оборванного хвоста | Действие `truncated_incomplete_tail_record`, valid terminal |
| **R3-05** | R3 State | Monotonic Ordinal Resequencing | Codex, Claude Code, Cline | Анализ монотонности ordinals, дедупликация | Нормализация `ord[i] == i`, фиксация degraded статуса |
| **R3-06** | R3 State | Cursor `state.vscdb` `ItemTable` Fix | Cursor IDE (Composer, Chat) | Балансировка JSON `{}` / `[]`, SQLite WAL cleanup | Пропуск credential-ключей, `integrity_check == ok` |
| **R3-07** | R3 State | Subagent Tree Orphanage Containment | Claude Code, OpenHands, Aider, Cline | `PR_SET_PDEATHSIG`, `CLONE_NEWPID`, `killpg` | Гарантированное уничтожение дерева процессов |
| **R3-08** | R3 State | Cross-Session Metadata Bleed | Claude Code, Cursor, Codex | Атомарное обновление `knownProjects` в `.claude.json` | Сохранение пользовательских ключей, пропуск credentials |
| **R3-09** | R3 State | Stale SQLite Index Desynchronization | OpenAI Codex, Cursor IDE | Dual scan (`index-first` vs `filesystem-all`) | Пометка отсутствующих сессий как `Unavailable` |
| **R3-10** | R3 State | Non-Atomic Rollback & Repair Race | Claude Code, Codex, Cursor | Транзакционный бэкап, атомарный `rename()`, квитанция | Сверка `restored_sha256 == original_sha256` при rollback |
| **R4-01** | R4 Policy | 7-Tier Policy Precedence Hierarchy | Claude, Codex, Cursor, Aider, Cline, OpenHands | Монотонная иерархия 1..7, `deny_unknown_fields` | Невозможность отмены Tier 1 deny через Tier 7 allow |
| **R4-02** | R4 Policy | Enterprise Lockdown & Immutability | Все агенты в CI/CD и предприятиях | `[security] immutable = true` в Tier 1 | Генерация `PolicyLockdownViolation` при попытке переопределения |
| **R4-03** | R4 Policy | Subtractive Deny over Landlock | Все агенты на Linux | Bind-mount `/dev/null` / `tmpfs 000`, 20k budget | Перекрытие файлов `.env`, fail-closed при превышении бюджета |
| **R4-04** | R4 Policy | SHA-256 HMAC Chained Logging Audit | Все агенты при проверках compliance | `O_APPEND \| O_NOFOLLOW`, $H_n = \text{HMAC}(H_{n-1})$ | Ошибка верификации цепочки при модификации байта |
| **R4-05** | R4 Policy | Enterprise CI/CD SARIF 2.1.0 Export | CI/CD раннеры, Claude, Codex, OpenHands | SARIF JSON Schema, правила `vetto.blocked-attempt` | Валидация схемы SARIF 2.1.0, санитизация текста |
| **R4-06** | R4 Policy | Regulatory Zero-Daemon Architecture | Все поддерживаемые агенты | Отказ от демонов, однопоточный префлайт перед fork | Отсутствие `daemon(3)`, чистое завершение супервизора |
| **R4-07** | R4 Policy | Regulatory Zero-Telemetry Isolation | Все агенты в закрытых контурах | Режим `network = "off"`, `socket(AF_INET)` -> `EPERM` | Отсутствие телеметрических библиотек в Cargo.lock |
| **R4-08** | R4 Policy | Bounded Conditional Evaluation | Все агенты в монорепозиториях | AST условий (`branch`, `file_exists`), лимиты поиска | Fail-closed при превышении `max_files=1000`/`max_depth=4` |
| **R4-09** | R4 Policy | Multi-Agent IPC Lateral Containment | Мульти-агентные группы, swarms | `CLONE_NEWIPC`, `CLONE_NEWNET`, seccomp ptrace ban | Изоляция `/dev/shm`, блокировка абстрактных сокетов |
| **R4-10** | R4 Policy | Multi-Stage Secret Scrubbing | Все агенты (PTY, logs, reports) | Aho-Corasick, Shannon Entropy, PEM/Token regex | Замена токенов на `[REDACTED]`, сохранение UTF-8 |
