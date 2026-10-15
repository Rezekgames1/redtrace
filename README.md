# RED//TRACE

Легковесный локальный SIEM и обозреватель событий для Windows, Linux и macOS. Проект хранит и ищет события на самом хосте, не требует Elasticsearch, JVM или отдельного сервера.

> Название `RED//TRACE` рабочее и может быть заменено без изменения архитектуры.

## Ранняя beta — 2026-10-13

Установка Windows SIEM, подключение Windows/Linux/macOS агентов, TLS, дата/время фильтры и сетевые результаты: **[Инструкция beta](docs/BETA_INSTALL.md)**. Актуальные пакеты: `outputs/beta-20261013/`. Это ранняя beta; старые release/load оценки ниже — исторические срезы.

GUI installers теперь есть для всех трёх проверенных платформ: Windows `.exe`, Linux x64 `.deb`, macOS Apple Silicon `.dmg` с `.app`. Каждый содержит встроенный frontend и core, отдельно ставить Node.js/Rust не требуется.

## Что уже работает

- Rust API только на `127.0.0.1:9710`;
- собственный DSL: поля, фразы, `AND`, `OR`, `NOT`, скобки и префикс `*`;
- дисковый query executor по сегментным postings и ограниченный кэш индексов;
- общий contains по всем значениям события, точные/contains/existence фильтры по полям и UI-конструктор;
- непрерывный сбор macOS Unified Log через `log stream` с backoff-рестартом;
- сбор Linux journald через JSON-вывод `journalctl` и поток `--follow`;
- read-only сбор Windows System, Security, PowerShell Operational и Sysmon через
  Event Log API (`EvtQuery`, pull `EvtSubscribe`, durable XML bookmarks);
- явный fallback `REDTRACE_WINDOWS_COLLECTOR=wevtutil` без зависимости от PowerShell;
- bounded-очередь ingestion с backpressure и метриками в `/api/health`;
- WAL с checksum, атомарной ротацией и восстановлением событий после перезапуска;
- неизменяемые JSONL-сегменты, атомарный manifest и retention по времени/размеру;
- словари полей/терминов и delta-varint postings для каждого сегмента;
- безопасный compaction малых сегментов с сохранением всех подтверждённых событий;
- durable checkpoints: journald cursor, Windows EventRecordID и временная отметка Unified Log;
- встроенный bounded-движок детектов: brute force, блокировка учётной записи,
  PowerShell Script Block, подозрительная командная строка и отказ `sudo`;
- надёжный журнал алертов с checksum, восстановлением и изоляцией повреждённых записей;
- отдельное рабочее пространство алертов с risk score, confidence, MITRE ATT&CK и
  переходом к событиям-доказательствам;
- интерактивный локальный UI в стилистике RedLab04;
- опциональный приём событий с других машин через легковесных агентов
  `redtrace-agent` (отдельный opt-in порт, токены, дедупликация по UID);
- план безопасной настройки Windows Audit;
- аудит входов 4624/4625, блокировок 4740 и создания процессов 4688;
- включение командной строки процесса и PowerShell Script Block Logging 4104;
- базовый профиль Sysmon с контролируемым объёмом событий;
- предварительный просмотр и модель отката до любых системных изменений.

## Локальный запуск

Терминал 1:

```bash
REDTRACE_ALLOW_UNAUTHENTICATED=1 cargo run
```

Терминал 2:

```bash
npm install
npm run dev
```

Откройте `http://localhost:3000`. Интерфейс показывает только события, полученные локальным нативным сборщиком. При недоступном API или пустом системном журнале отображается пустое состояние — тестовые события не подставляются.

Desktop-режим (Tauri/Wry, Node.js пользователю не нужен):

```bash
npm run desktop:dev
# release-проверка без упаковки установщика
npm run desktop:build -- --no-bundle
```

Desktop-оболочка запускает Rust-ядро как sidecar, передаёт ему случайный 256-битный сессионный токен и завершает sidecar при выходе. Повторный запуск переводит фокус на уже открытое окно. Для Windows, Linux и macOS sidecar получает имя по Rust target triple.

На Windows по умолчанию используются нативные Event Log API и pull subscription. XML bookmark сохраняется после записи события в WAL. Старый polling включается явно через `REDTRACE_WINDOWS_COLLECTOR=wevtutil`. На macOS используется Unified Log, на Linux — journald.

В desktop-режиме токен API создаётся автоматически. Для standalone-ядра нужен `REDTRACE_API_TOKEN` длиной не менее 32 байт. Открытый локальный dev-режим включается явно через `REDTRACE_ALLOW_UNAUTHENTICATED=1`; слишком короткий заданный токен приводит к отказу запуска.

Окно macOS можно изменить перед запуском, например `REDTRACE_LOOKBACK=24h cargo run`; допустимы значения с суффиксами `m`, `h` и `d`. Для Security/Sysmon/PowerShell журналов Windows и расширенного Linux audit нужны соответствующие права и заранее включённые системные политики — RED//TRACE самовольно их не изменяет.

По умолчанию сегмент создаётся после 8 МБ активного WAL, восемь малых сегментов объединяются, локальная база ограничена 512 МБ и хранится 7 дней. Журнал алертов ограничен 32 МБ. Параметры можно изменить через `REDTRACE_SEGMENT_MB`, `REDTRACE_COMPACT_SEGMENTS`, `REDTRACE_MAX_STORAGE_MB`, `REDTRACE_RETENTION_DAYS` и `REDTRACE_MAX_ALERT_MB`. Каталог и файлы данных на Unix доступны только текущему пользователю.

WAL отделяет оборванные строки от новых записей и восстанавливает checksum-valid records. При обнаружении повреждения полный original сохраняется в `wal-quarantine` перед заменой WAL и продолжением rotation. Одновременный второй collector того же WAL отклоняется. История восстановления видна в health/diagnostics и «Источниках»; quarantine имеет отдельный бюджет 256 MiB. Проверки и границы гарантии: [WAL recovery](docs/WAL_RECOVERY.md).

## Сбор логов с других машин через агентов

Локальный API по-прежнему слушает только `127.0.0.1:9710`. Приём событий от
удалённых агентов — отдельный opt-in контур на собственном порту:

1. Для удалённого приёма задайте `REDTRACE_INGEST_BIND`, `REDTRACE_INGEST_CERT` и `REDTRACE_INGEST_KEY` (PEM-сертификат с подходящим DNS/IP SAN и приватный ключ вне исходников). Non-loopback listener без TLS не запускается. Без `REDTRACE_INGEST_BIND` порт не открывается. HTTP разрешён только для loopback-проверок.
2. Выпустите токен агента на машине с ядром:

   ```bash
   curl -s -X POST http://127.0.0.1:9710/api/agents \
     -H 'Content-Type: application/json' -d '{"name":"web-01"}'
   ```

   Токен показывается один раз; в `agents.json` хранится только SHA-256-хэш.

3. На целевой машине запустите агент:

   ```bash
   redtrace-agent --server https://<имя-ядра>:9711 --name web-01
   ```

Перед запуском задайте `REDTRACE_AGENT_TOKEN` в окружении процесса агента. Для частного CA задайте `REDTRACE_AGENT_CA` — путь к PEM-сертификату доверенного CA. Проверка сертификата и имени сервера обязательна; redirects отключены.

Агент переиспользует нативные коллекторы ядра (Windows Event Log API на Windows),
сохраняет собственный checkpoint только после подтверждения батча сервером
(at-least-once), буферизует до 20 000 событий / 32 МБ при недоступном сервере и
отправляет heartbeat каждые 30 секунд. Сервер помечает события полями
`agent.id`, `agent.name`, `host.name`, считает UID в области агента и не
допускает чужие курсоры в локальные checkpoints. Список агентов и их
состояние видны в `/api/sources` и `/api/health`; отзыв токена —
`DELETE /api/agents/{id}`.

Сервер подтверждает батч только после WAL. Повторная отправка после потерянного ответа безопасна. Отклонённые батчи разделяются; непринимаемое одиночное событие сохраняется с fsync в ограниченный локальный quarantine (16 МБ), затем checkpoint продвигается. При заполненном quarantine очередь сохраняется и повторяется. Батч — не более 1000 событий и 8 МБ. Для Security нужны соответствующие права, Sysmon должен быть установлен отдельно.

В UI «Источники» доступны выпуск токена, список машин, last_seen, число событий и отзыв токена. Токен отображается однократно и не сохраняется в браузере.

## Поиск и фильтры

В режиме **Contains · все поля** вводите обычный текст: он ищется как непрерывная подстрока во всех значениях полей, сообщении, источнике, времени и UID, без учёта регистра. Кавычки, двоеточия и обратные слеши автоматически экранируются. Поиск не пересекает границы значений разных полей.

**Добавить фильтр** позволяет выбрать поле, «Равно», «Содержит», «Существует» и исключение. `＋`/`−` в деталях добавляют точное сравнение/исключение. Фильтр сохраняет логику существующего OR-запроса. Пагинация и экспорт используют последний выполненный запрос.

При вводе появляются подсказки. В DSL `agent.n` предлагает `agent.name=`, а `agent.name="ka` — реальные значения, например `"kali-wsl"`. В contains-режиме предлагаются подходящие значения, в конструкторе фильтра — поля и значения выбранного поля. `↑`/`↓` выбирают вариант, Enter вставляет, Esc закрывает список; работает выбор мышью. Значения берутся из показанных событий, а не из всей базы. Подробности и проверенный базовый статус: [Подсказки и статус](docs/BASIC_STATUS_AND_FILTERS.md).

События поступают автоматически через authenticated SSE: ручное обновление журналов в ленте не требуется. **Пауза** замораживает только отображение, сбор продолжается; **В прямой эфир** догоняет новые события. Просмотр старых страниц/прокрутка ставит ленту на паузу, выбранное событие остаётся открытым. По умолчанию боковые панели и график закрыты. Ctrl/Cmd K — поиск, Esc — закрыть панели. При обрыве соединения UI переподключается автоматически.

Результаты аудита GUI, скриншоты и end-to-end проверки: [GUI audit](docs/GUI_AUDIT.md).

**Представления** сохраняют выполненный запрос, режим поиска и колонки локально между загрузками интерфейса. **Колонки** позволяют выбрать поля, поменять порядок и вернуться к стандартному набору. Описание события остаётся обязательным; максимум 8 колонок и 32 представления. Подробности и результаты короткой нагрузки: [Представления и нагрузочная проверка](docs/VIEWS_AND_LOAD.md).

В режиме **Запрос · поля / DSL**:

```text
event.id=4625
user.name="Administrator"
process.command_line~"powershell"
process.command_line:*
NOT user.name="root"
(event.id=4625 OR event.id=4624) AND source~"security"
"часть сообщения"
*="конкретное полное значение любого поля"
```

`=` — полное значение, `~` — подстрока, `:*` — существующее поле. Старые `event.id:4625`, `source:windows.*`, `AND`, `OR`, `NOT`, скобки поддерживаются. Общий bare-text поиск теперь проверяет все значения; строки с пробелами в DSL заключайте в кавычки. Литерал `*` внутри кавычек не является wildcard.

Парсер ограничивает запрос до и во время разбора: 8192 UTF-8 байта, 256 токенов, 16 одновременно вложенных скобок/`NOT` и 64 узла AST. Превышение возвращает HTTP 400 с байтовой позицией и действующими лимитами. Лимиты можно уменьшить через `REDTRACE_QUERY_MAX_BYTES`, `REDTRACE_QUERY_MAX_TOKENS`, `REDTRACE_QUERY_MAX_DEPTH`, `REDTRACE_QUERY_MAX_NODES`; они видны в `/api/health` и `/api/diagnostics`. Подробности: [Бюджеты query parser](docs/QUERY_LIMITS.md).

## API

```text
GET /api/health
GET /api/live                   authenticated SSE revision notifications
GET /api/search?q=event.id:4625 OR process.name:"powershell.exe"&limit=100
GET /api/aggregations?q=*&limit=50000
GET /api/alerts?limit=100
GET /api/detections/rules
GET /api/diagnostics
GET /api/export?q=*&format=jsonl&limit=10000
GET /api/audit/windows/plan
GET /api/audit/windows/status
GET /api/agents
POST /api/agents {"name":"web-01"}
DELETE /api/agents/{id}

ingest-порт (только при REDTRACE_INGEST_BIND):
POST /ingest/v1/events      заголовок x-redtrace-ingest-token
POST /ingest/v1/heartbeat   заголовок x-redtrace-ingest-token
GET /ingest/v1/health
```

## Проверка

```bash
cargo fmt --check
cargo test
npm run build
npm run lint
npm run desktop:ui:build
cargo check --manifest-path src-tauri/Cargo.toml
./scripts/smoke-crash-recovery.sh
./scripts/load-search-smoke.sh
./scripts/smoke-agent-ingest.sh
```

## Безопасность мастера аудита

Windows NSIS устанавливает SIEM с UAC в `Program Files` для всех пользователей. Установленный audit helper доступен без dev-флага: проверяются защищённые owner/DACL и digest pin; отдельный helper получает только allowlisted операции через локальный named pipe, проверяет PID/путь IPC-peer и запрашивает UAC на apply/rollback. Snapshot создаётся в защищённом каталоге `%SystemRoot%\System32\REDTRACE-audit-snapshots`; откат audit затрагивает только выбранные subcategories/registry values и проверяет конфликты. Незащищённая portable/dev copy остаётся preview-only. Реальные проверки: [Admin install / audit](docs/ADMIN_INSTALL_AND_AUDIT.md).

В том же мастере есть отдельный Sysmon preview/install: одобренный Microsoft Sysmon 15.22 проверяется через Authenticode/WinVerifyTrust и public SHA-256 pin. Frozen bytes передаются helper через IPC; caller-controlled filepath не читается с повышенными правами. Используется встроенный XML-профиль, существующая установка не заменяется. Отдельная операция выдаёт текущему пользователю только read-доступ к Security/Sysmon, с snapshot/restore ACL. Командные строки и PowerShell-журналы могут содержать секреты — это показывается до включения политик. Dev-helper и установщик пока не подписаны.

Windows-проверки:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-desktop-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-installer-windows.ps1
node scripts\smoke-desktop-ui.mjs
node scripts\smoke-desktop-ui.mjs --audit-ui
```

Последняя команда реально меняет выбранные политики с UAC, проверяет их и восстанавливает snapshot; запускайте её только при разрешённом apply/rollback. Результаты и оставшиеся release gates: [Windows validation](docs/WINDOWS_VALIDATION.md).

Подробности: [архитектура](docs/ARCHITECTURE.md) и [профиль Windows Audit](docs/WINDOWS_AUDIT.md).

Подключение Windows endpoints: [Windows agents](docs/WINDOWS_AGENTS.md).

Linux core/desktop/agents и результаты проверок: [Linux SIEM](docs/LINUX.md).

Текущий release-статус — закрытая alpha / контролируемый пилот. Подтверждённые проверки и незакрытые production gates: [Production readiness](docs/PRODUCTION_READINESS.md).

Для текущих исходников 0.2.0: [настройка collector/агентов, источников, rules, PKI и backup](docs/SETUP_AND_OPERATIONS.md). Реализация и границы проверки: [срез разработки](docs/DEVELOPMENT_20261013.md), [нативная Windows-проверка 15 октября](docs/WINDOWS_NATIVE_VALIDATION_20261015.md). Пакеты `outputs/beta-20261013` сохраняют предыдущий срез, новые функции требуют пересборки.

Исторический план следующих этапов: [План реализации](docs/IMPLEMENTATION_PLAN.md). Публичная поставка и длительные native reliability gates остаются отдельной работой.
