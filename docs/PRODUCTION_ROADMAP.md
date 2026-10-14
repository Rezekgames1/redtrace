# RED//TRACE: roadmap до production

## Оценка текущего состояния

Актуальная оценка на 08.10.2026: `docs/PRODUCTION_READINESS.md`. Исполняемый план следующих итераций с зависимостями и критериями готовности: `docs/IMPLEMENTATION_PLAN.md`. Ниже roadmap сохраняет целевые критерии; исторические результаты macOS не заменяют новые Windows/Linux проверки.

RED//TRACE сейчас является закрытой alpha локального обозревателя/лёгкого SIEM с проверенными Windows/Linux сценариями:

- Rust API слушает только `127.0.0.1`;
- macOS Unified Log и Linux journald читаются потоково в режиме read-only;
- Windows System/Security/PowerShell/Sysmon читаются через native Event Log subscription/bookmarks; `wevtutil` — явный fallback;
- активный WAL индексируется в памяти, исторические сегменты ищутся по дисковым postings;
- подтверждённые пакеты записываются в WAL, атомарно переносятся в неизменяемые сегменты и восстанавливаются после перезапуска;
- ingestion ограничен bounded-очередью и публикует метрики здоровья;
- работает собственный DSL с exact/contains/existence и общим contains;
- GUI поддерживает authenticated live SSE, pause/resume, детали, сохранённые представления и колонки;
- Windows dev Audit helper имеет allowlist/UAC/snapshots/verify/rollback; production signing gate не закрыт.

Query executor читает сегментные postings, checkpoints привязаны к durable WAL. Linux продолжает по journald cursor, Windows — по native XML bookmark, macOS — по timestamp. Есть bounded ruleset, alerts, TLS agents и собранные unsigned NSIS/.deb. Подтверждён короткий burst; длинный runner завершился FAIL и не прошёл финальную сверку. Подписанная production-поставка, строгие execution/storage budgets и 24/7 reliability ещё не подтверждены.

## Целевая production-архитектура

```text
platform collectors
       |
       v
bounded ingestion queue -> parser/normalizer -> redaction policy
       |                                         |
       |                                         v
       +-------------------------------> active WAL
                                                   |
                                                   v
                                      immutable disk segments
                                      /        |          \
                              field index  text index  time index
                                      \        |          /
                                       query + aggregation engine
                                                   |
                         detection engine <-> local IPC/API <-> desktop UI
                                                   |
                                      export / diagnostics / audit wizard
```

Каждый этап обязан иметь bounded-очередь и backpressure. Потеря UI, перезапуск процесса или повреждение одного сегмента не должны приводить к потере уже подтверждённых в WAL событий.

## P0 — обязательные блоки до закрытого alpha

### 1. Непрерывный ingestion

- заменить повторный `log show --last ...` на непрерывный поток новых событий;
- хранить checkpoint/cursor отдельно для каждого источника;
- использовать bounded channel и backpressure;
- пакетировать запись и индексирование;
- дедуплицировать события по стабильному fingerprint, а не только внутри одного прохода;
- отслеживать dropped, delayed, malformed и duplicate events;
- корректно завершать процесс с flush WAL;
- не блокировать запуск API во время первоначального чтения журналов.

Критерий готовности: 24-часовой soak-тест не теряет события при перезапуске, не имеет неограниченного роста памяти и восстанавливается после переполнения очереди.

### 2. Дисковое хранилище

- append-only WAL с checksum и fsync-политикой;
- неизменяемые сегменты событий;
- словарь полей и значений;
- postings/bitmaps для точных фильтров;
- текстовый индекс и временной индекс;
- manifest/catalog с атомарной заменой;
- compaction малых сегментов;
- retention по времени и максимальному размеру;
- восстановление после оборванной записи;
- версионирование формата и миграции;
- файловые разрешения только для текущего пользователя;
- опциональное шифрование локальной базы.

Критерий готовности: после принудительного завершения процесса база открывается без потери подтверждённых событий; повреждённый сегмент изолируется и диагностируется.

### 3. Полноценные коллекторы

macOS:

- Unified Log streaming;
- Endpoint Security для exec/fork/exit/file/network событий;
- OpenBSM/audit при необходимости расширенного аудита;
- корректная обработка privacy-redacted значений;
- проверка Full Disk Access и понятная диагностика разрешений.

Windows:

- Windows Event Log API через subscription/bookmark, без периодического PowerShell;
- Security, System, PowerShell Operational и Sysmon channels;
- корректный render XML и SID/account resolution;
- bookmarks, channel rollover и восстановление после reboot;
- отдельный привилегированный helper только для настройки аудита.

Linux:

- journald cursor API;
- auditd/netlink или чтение audit log с checkpoint;
- auth, sudo, sshd, process execution и service events;
- поддержка log rotation и разных дистрибутивов.

Критерий готовности: каждый поддерживаемый источник имеет fixture-тесты, интеграционный тест и тест продолжения с checkpoint после перезапуска.

### 4. Нормализованная схема событий

- определить версионируемую схему, близкую по смыслу к ECS/OCSF, но без зависимости от Elasticsearch;
- отделить обязательные typed-поля от динамических attributes;
- хранить timestamp в UTC с исходной timezone;
- ввести стабильный event UID/fingerprint;
- нормализовать process entity: PID, PPID, executable, command line, user, hash;
- нормализовать network entity: source/destination IP, port, protocol;
- сохранить исходное событие и информацию о parser/source version;
- различать отсутствующее, скрытое системой и неприменимое значение;
- добавить redaction policy для токенов, паролей и персональных данных.

Критерий готовности: одна и та же сущность имеет одинаковое имя и тип на Windows, Linux и macOS.

### 5. Надёжный поисковый движок

- поиск по диапазону времени и числовым диапазонам;
- `exists`, wildcard/prefix, CIDR и case-insensitive поля;
- сортировка, cursor pagination и стабильный порядок;
- phrase search и нормальная токенизация Unicode;
- time histogram, terms aggregation и top values;
- отмена долгого запроса и лимиты памяти/времени;
- защита от запросов с экспоненциальной стоимостью;
- schema discovery и статистика покрытия полей;
- версионирование синтаксиса DSL;
- fuzzing lexer/parser/query executor.

Критерий готовности: p95 поиска за 24 часа локальных событий укладывается в целевой бюджет без роста памяти пропорционально всей базе.

### 6. Движок детектирования

Без этого продукт остаётся обозревателем логов, а не SIEM.

- правила над входящим потоком и историческими событиями;
- threshold, sequence/correlation и absence rules;
- suppression/deduplication алертов;
- severity, confidence, risk score и MITRE ATT&CK mapping;
- состояние правила и bounded окна корреляции;
- тестовые события и unit-тесты для каждого правила;
- встроенный минимальный ruleset для входов, privilege escalation, suspicious process execution и persistence;
- пользовательские правила без выполнения произвольного кода;
- карточка алерта с доказательствами и переходом к исходным событиям.

Критерий готовности: правила детерминированы, воспроизводимы на fixture-наборе и не могут остановить ingestion.

Текущий статус: реализована первая вертикаль — threshold для отказов входа, блокировка Windows-аккаунта, PowerShell 4104, подозрительные command line и отказ `sudo`; есть suppression, bounded-окна, risk/confidence/MITRE, durable alert log, API и UI с доказательствами. До закрытия блока остаются sequence/absence rules, исторический replay, конфигурируемый безопасный формат пользовательских правил и полный fixture-набор для всех ОС.

Локальный release-gate на macOS: 32 Rust-теста, clippy без предупреждений, UI lint/build/render test, crash/restart 65→65 реальных событий, 500 поисковых запросов с concurrency 20 (p95 около 11 мс, RSS ядра около 12 МБ). Эти цифры не заменяют 24/72-часовой soak и нативную проверку Windows/Linux.

## P1 — обязательные блоки до публичной beta

### 7. Безопасность локального приложения

- заменить постоянный открытый HTTP-порт на Tauri IPC, Unix domain socket или named pipe;
- если HTTP сохраняется — случайный session token, строгий Host/Origin check и динамический порт;
- разделить непривилегированный UI/core и минимальный privileged helper;
- запретить UI передавать произвольные команды helper-процессу;
- подписывать запросы на изменение аудита и требовать явное подтверждение;
- threat model для malicious local process, malicious webpage, tampered update и poisoned log;
- escaping и лимиты для всех отображаемых log values;
- защита экспортов от formula injection и path traversal;
- secret scanning, dependency audit и SBOM.

### 8. Desktop-поставка

- единый desktop shell, предпочтительно Tauri/Wry, без обязательного Node.js у пользователя;
- встраивание статических UI assets в приложение;
- управление жизненным циклом core-процесса;
- single-instance lock;
- корректная работа sleep/wake, logout и reboot;
- системный tray и понятный статус сбора;
- MSI/MSIX для Windows, signed/notarized DMG/PKG для macOS, deb/rpm/AppImage для Linux;
- code signing, notarization и защищённый auto-update с rollback;
- каналы stable/beta и совместимость формата базы при downgrade.

### 9. Мастер аудита

- чтение и отображение текущего состояния до изменений;
- backup audit policy/registry/config;
- preview точных изменений;
- elevation только на apply/rollback;
- проверка результата после каждой операции;
- транзакционный rollback при частичной ошибке;
- проверка подписи и издателя Sysmon;
- установка только после явного согласия;
- отчёт о том, какие дополнительные чувствительные данные начнут собираться.

### 10. Production UI/UX

- реальный time picker и timezone;
- saved searches, pinned filters и история запросов;
- управление колонками и сохранение ширины/порядка;
- виртуализация больших таблиц;
- live/pause режим и индикатор задержки ingestion;
- статус каждого источника, permissions и dropped events;
- просмотр процесса, дерева родителей и связанных сетевых/файловых событий;
- alerts/detections workspace;
- экспорт JSON/JSONL/CSV с redaction policy;
- accessibility, keyboard navigation и локализация;
- диагностика пустого результата: нет событий, нет разрешений или источник сломан.

## P2 — требования к production-релизу

### 11. Наблюдаемость и поддержка

- структурированные внутренние логи с rotation;
- health состояния WAL, сегментов, collectors и rule engine;
- локальная страница диагностики без содержимого пользовательских событий;
- opt-in crash reports без логов и персональных данных;
- support bundle с явным preview состава;
- документированные error codes и recovery procedures.

### 12. Тестирование

- unit-тесты parser/normalizer/index/storage;
- golden fixtures для каждой ОС и версии источника;
- property tests для WAL и сегментов;
- fuzz tests для DSL, JSON/XML/event parsers;
- crash-consistency и corruption tests;
- нагрузочные тесты на burst ingestion и высокую cardinality;
- 24/72-часовые soak-тесты;
- end-to-end тесты desktop UI;
- CI matrix Windows/macOS/Linux;
- тесты upgrade/downgrade базы и приложения;
- измерение RSS, CPU, disk write amplification и query latency на каждом release.

### 13. Privacy, compliance и документация

- понятная политика локального хранения;
- перечень собираемых полей и разрешений;
- настройка retention до включения расширенного аудита;
- secure erase в пределах возможностей файловой системы;
- лицензии зависимостей и third-party notices;
- threat model и security reporting policy;
- руководство администратора, пользователя и разработчика;
- release notes и политика совместимости.

## Рекомендуемая последовательность релизов

### Milestone A — durable macOS alpha

Непрерывный Unified Log ingestion, WAL, сегменты, восстановление, реальный time histogram и статус потерь. Только macOS, без обещания полноценного SIEM.

### Milestone B — macOS detection alpha

Endpoint Security, базовые правила, alerts workspace, экспорт и подписанная macOS-сборка.

### Milestone C — cross-platform beta

Windows Event Log/Sysmon и Linux journald/auditd, единая схема, установщики, safe audit wizard и CI matrix.

### Milestone D — production candidate

Security hardening, crash consistency, auto-update, миграции, 72-часовые soak-тесты, документация и release gates.

## Release gates

Production-релиз запрещён, пока не выполнены все условия:

- нет потерь подтверждённых событий при crash/restart;
- нет неограниченных очередей или структур в памяти;
- все поддерживаемые источники продолжают чтение с checkpoint;
- база восстанавливается или изолирует повреждённый сегмент;
- privileged операции отделены и требуют подтверждения;
- приложение и обновления подписаны;
- все три ОС проходят CI и интеграционные тесты;
- выполнены soak/load/fuzz/security тесты;
- UI явно показывает задержку, ошибки источников и dropped events;
- documented rollback существует для приложения, базы и аудита;
- реальное потребление ресурсов соответствует заявленным бюджетам.

## Приоритет ближайшей реализации

Offsets, native Windows subscriptions/bookmarks, journald cursors, cursor pagination, первые детекты/alerts, TLS agents и desktop уже реализованы. Их нельзя считать незавершёнными только из-за старых формулировок roadmap.

Ближайшие итерации:

1. Query parser/executor budgets, cancellation/concurrency; bounded Linux follow и ingest metadata/quotas.
2. Retention age/hard cap и deterministic storage failure tests.
3. Первый реальный remote endpoint по сети существующим агентом.
4. Service/daemon lifecycle collector/agent; durable disk spool и continuous agent delivery вместо default poll 5s.
5. GUI onboarding/host health и lifecycle токенов/CA/сертификатов.
6. Production helper trust/signing, минимальная distro matrix и upgrade/recovery gates.

Полный порядок, small-commit breakdown и acceptance: `docs/IMPLEMENTATION_PLAN.md`. Короткая диагностика прежнего long-run failure сопровождает этапы; новые длительные тесты запускаются только после нового указания владельца.
