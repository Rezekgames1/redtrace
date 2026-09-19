# RED//TRACE: roadmap до production

## Оценка текущего состояния

RED//TRACE сейчас является вертикальным прототипом локального обозревателя событий:

- Rust API слушает только `127.0.0.1`;
- macOS Unified Log читается в режиме read-only;
- события нормализуются и индексируются в оперативной памяти;
- работает собственный поисковый DSL;
- интерфейс позволяет искать события, фильтровать поля и изучать процессный контекст;
- Windows Audit представлен только как безопасный preview-план.

Это подтверждает архитектурную идею, но ещё не обеспечивает непрерывный сбор, сохранность данных, детектирование угроз и безопасную поставку. До публичного production-релиза проект следует считать pre-alpha.

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

Следующий кодовый этап должен включать только фундамент ingestion/storage:

1. `Collector` trait с потоковой выдачей событий и checkpoint.
2. Bounded ingestion queue с метриками backpressure/drop.
3. WAL v1 с checksum и recovery-тестами.
4. Стабильный event UID и versioned normalized schema.
5. Инкрементальное добавление в индекс без полной замены.
6. Реальный status API: lag, queue depth, last event, dropped, WAL size.

Детекты, новые экраны и установщики следует строить после появления гарантированно надёжного потока и хранения: иначе они будут опираться на данные, которые могут исчезать или дублироваться.
