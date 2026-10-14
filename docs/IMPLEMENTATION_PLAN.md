# План дальнейшей реализации RED//TRACE

Дата: 08.10.2026. Базовый source milestone: `6ed560b`. Текущий статус — закрытая alpha / контролируемый read-only пилот. Документ задаёт будущие работы, а не утверждает, что release gates уже закрыты.

Обновление 13.10.2026: первая ранняя beta собрана локально — `outputs/beta-20261013/`, инструкция `BETA_INSTALL.md`, проверки `BETA_VALIDATION_20261013.md`. M1 budgets/retention/bounded readers, M3 service source implementation и M4 durable spool реализованы; M2 direct physical MacBook LAN case выполнен, M6 token lifecycle реализован. Добавлены UI/API date/time filters. Старые утверждения ниже об RAM-only outbox и отсутствии service mode устарели. Следующие пользовательские этапы — native Linux auditd reader/aggregation, macOS Endpoint Security integration, свежие macOS/Linux GUI packages и unattended boot/install validation; production signing/длительный gate отдельно. Дополнительные security reviews остановлены владельцем.

## Что уже есть — повторно реализовывать не нужно

- Native Windows Event Log/Sysmon, Linux journald и существующий macOS Unified Log collector.
- WAL, сегменты, дисковые индексы, checkpoints, дедупликация и первые детекты.
- HTTPS agent ingest, индивидуальные токены, CA/SAN verification, heartbeat, ACK после WAL, retry/quarantine.
- GUI регистрации/отзыва агентов, live SSE, pause/resume, детали и экспорт.
- Exact/contains/existence-фильтры, общий contains, локальные представления и выбор колонок.
- Windows/Linux desktop-сборки и воспроизводимые короткие проверки.

Ограничения, которые нельзя путать с готовыми возможностями:

- Отдельный физический remote host ещё не проверен; Windows TLS process test выполнялся на одном хосте.
- Агент сейчас собирает периодическими проходами: default poll 5s (`src/agent/mod.rs:13`, `src/bin/agent.rs:172–178`). GUI live не делает этот путь автоматически непрерывной подпиской.
- Agent outbox — RAM `VecDeque`, а не durable disk spool (`src/agent/mod.rs:291–320`). Checkpoint/quarantine сохраняются, но crash/offline recovery зависит также от доступности исходного журнала.
- Desktop закрывает core вместе с окном (`src-tauri/src/main.rs:73–83`); unattended service/daemon lifecycle отсутствует.
- Длинный тест не прошёл финальную проверку. Его повтор отменён владельцем; новая длительная проверка требует отдельного указания.

## Приоритеты и порядок

**P0** — блокеры надёжного и безопасного расширения/production release. **P1** — полноценная эксплуатация нескольких хостов. **P2** — расширение телеметрии, расследований и правил.

Рекомендуемая последовательность небольших итераций:

1. Ограничения query/ingest/records и корректный retention: **M1**.
2. Один реальный remote endpoint существующим агентом: **M2**, без ожидания нового onboarding wizard.
3. Фоновый collector/agent и durable offline-доставка: **M3–M4**.
4. Onboarding и управление агентами/сертификатами: **M5–M6**.
5. Короткие failure-injection проверки выполняются на каждом этапе; диагностика прежнего сбоя: **M7**.
6. Signing, платформенная поставка и release gates: **M8**, часть задач можно готовить параллельно.
7. Расширенные источники и аналитика: **M9–M10**.

Signing и согласованные reliability gates обязательны до production, даже если их реализация завершится после функциональных этапов.

## M1. Ограничения ресурсов и сохранность — P0

### Query

- **Выполнено 08.10.2026:** UTF-8 query bytes, tokens, nesting depth и AST nodes ограничиваются **до/во время** parsing. Скобки и `NOT` расходуют общий depth budget до рекурсивного вызова. Настройки, API и проверки: `QUERY_LIMITS.md`.
- Сделать bounded top-k/cursor search без материализации всех совпавших events; использовать in-place postings accumulation.
- Добавить cooperative deadline/cancellation и semaphore для конкурентных запросов. Timeout должен прекращать работу, а не только ожидание ответа.
- Обеспечить согласованный snapshot RAM/segments при rotation/compaction, без transient двойного счёта.

### Ingest и collectors

- Валидировать длины/значения host, OS, architecture и agent version; ограничить общий размер нормализованного event.
- Добавить global/per-agent concurrent batch, byte-rate и queued-byte budgets с понятным backpressure. Агент должен сохранять pending batch и корректно обрабатывать Retry-After.
- Применить bounded record reader к Linux follow/stderr, а не только backfill; oversized/invalid records должны иметь видимую диагностику и определённую checkpoint/quarantine-политику.

### Storage

- **Выполнено 12.10.2026:** WAL framing/merged-record recovery, exact-original quarantine, cooperating writer ownership и regression crash/rotation/replay checks (`WAL_RECOVERY.md`). Конкретный рабочий WAL blocker устранён; cap/age/cancellation остаются отдельными пунктами ниже.
- Enforce hard storage cap, включая единственный oversized segment и временный запас на compaction.
- Сохранить event-age/time boundaries при compaction, не обновлять возраст старых данных как новых.
- Ограничить размер выходного сегмента; определить поведение disk-full и безопасное recovery/migration старого manifest.

**Готово, когда:** deep/high-cardinality queries отклоняются или завершаются в установленном бюджете; отменённая работа прекращается; flooding одного агента не вытесняет остальные; память/очереди ограничены в bytes; retention сохраняет возраст данных и cap; подтверждённые события проходят deterministic crash/rotation проверки. Бюджеты фиксируются в конфигурации и health; численные значения выбираются по измерениям, а не объявляются SLA заранее.

**Затрагиваемые места:** `src/query.rs`, `src/index.rs`, `src/storage/segment_index.rs`, `src/storage/segments.rs`, `src/main.rs`, `src/ingest.rs`, `src/collector/linux.rs`.

## M2. Первое реальное подключение по сети — P1

- Получить от владельца доступный Windows/Linux endpoint, адрес collector и разрешённую сеть. Начать с одного хоста, затем проверить второй ОС.
- Подготовить серверный сертификат с правильным SAN и доверенный CA; хранить ключи/токены вне исходников.
- Включить TLS listener только на нужном интерфейсе; документировать точечное firewall правило. GUI/API оставить локальными.
- Зарегистрировать endpoint существующим GUI, установить бинарник агента и проверить права чтения журналов.
- Создать диагностические события на endpoint, проверить поля host/agent, UID, поиск, детекты и live-отображение на collector.
- Проверить disconnect/reconnect, collector restart, потерянный ACK/replay, неправильные CA/SAN, revoked token и hostname change.

**Готово, когда:** реально удалённые события однозначно относятся к endpoint; повтор не увеличивает число записей; ACK соответствует durable storage; отозванный токен отклоняется; documented permission/network errors понятны. Задержка измеряется отдельно для действующего poll-пути; субсекундная remote-доставка не обещается до M4.

**Зависимости:** доступный тестовый хост/сеть/PKI. Закрытый ручной пилот возможен существующим протоколом; расширенный rollout — после M1.

## M3. Постоянный сбор без открытого GUI — P1, production gate

- Добавить Windows Service, systemd и позднее launchd lifecycle для collector и отдельного агента: install/start/stop/status/restart/uninstall, boot start и crash recovery.
- Сохранить portable desktop-owned mode; persistent mode должен продолжать сбор после закрытия GUI.
- UI подключается к существующему сервису через защищённую local IPC/session-auth схему. Не переносить session token в URL/аргументы процесса и не открывать admin API наружу.
- Разделить service identity/data directory, UI-session auth и agent credentials. Применять минимальные права доступа к журналам; LocalSystem/root не выбирать автоматически как универсальный способ чтения.
- Добавить проверку listener PID/path/version и single-collector/data-lock. Не завершать неизвестный процесс для освобождения порта.
- Настройка служб/прав/драйверов — отдельная явно подтверждённая административная операция; rollback не затрагивает сторонний Sysmon.

**Готово, когда:** GUI close/logout не останавливают persistent collector; reboot поднимает сервис; crash recovery восстанавливает confirmed events; unknown listener/версия/недостаточные права диагностируются; portable mode не регрессирует.

## M4. Durable agent spool и низкая задержка — P1

- Добавить ограниченный дисковый outbox с checksum/versioning, fsync/atomic ACK progress и recovery после force-kill/reboot.
- Разделить read/spool cursor и server-ACK progress: чтение вперёд допустимо только после durable local spool, удаление pending — после durable server ACK.
- Задать политику заполнения spool/quarantine и корректные счётчики отказов enqueue/потерь. Сейчас `Outbox::push` возвращается при cap без обновления overflow counter; это нужно отдельно покрыть тестами, не объявлять автоматически потерей исходного журнала.
- Перевести remote agent на continuous platform stream + bounded producer/consumer queue. Существующий polling оставить как явный fallback.
- Отправлять малые batches по count/bytes/maximum dwell time, не ждать heartbeat. Повторно использовать TLS client/connection; reconnect backoff с jitter.
- Снизить влияние исторического backfill на live/heartbeat, не продвигая checkpoint через неподтверждённую историю.

**Готово, когда:** endpoint продолжает durable сбор при недоступном collector; force-kill и удаление/rotation исходного журнала не теряют уже spooled events; replay идемпотентен; spool остаётся в byte cap. Для здоровой LAN steady-path начальная целевая задержка — p95 ≤2s, подтверждаемая измерением; catch-up backlog оценивается отдельно и не выдаётся за тот же SLA.

**Зависимости:** M1 и M2; service lifecycle M3 нужен для unattended acceptance.

## M5. Onboarding и управление хостами — P1

- GUI master: выбрать interface/port, показать состояние TLS/SAN/expiry, включить listener явно, проверить доступность.
- Выпуск enrollment/config с минимальными ручными шагами; токен показывается один раз и передаётся в защищённое хранилище endpoint. Agent installer не требует полного desktop/WebView/Node.
- Карточка хоста: OS/version, collectors, permissions, last heartbeat, last event, backlog/spool bytes, retry/quarantine/dropped и delivery lag.
- Показать различие online/idle/stale/offline/degraded; heartbeat не считать доказательством поступления событий.
- Host search/filter, быстрый переход к событиям/алертам хоста, rename/revoke и понятные recovery-инструкции.

**Готово, когда:** новый host подключается по документированному мастеру; ошибки CA/SAN/firewall/permissions однозначны; интерфейс не сохраняет выданные секреты в localStorage/URL/logs; offline/backlog видны до ручного расследования.

## M6. Lifecycle идентичности и сертификатов — P1, production gate

- Ротация токена без неоднозначного agent ID и duplicate scopes; контролируемый overlap старого/нового credential, expiry и отзыв.
- CA/server-certificate rotation/reload, предупреждения об expiry, fail-closed при неправильном trust chain. Обновление trust на endpoint документировано.
- Защищённые credential/config files или OS secret store, ограничения чтения service identity, redaction внутренних логов.
- Запрет token CLI arguments в production deployment guide; plaintext в исходниках/репозитории/diagnostics отсутствует.
- Опциональный mTLS вводить при требованиях эксплуатации после базового управления PKI; не переписывать работающий HTTPS/token transport без совместимости.

**Готово, когда:** rotation/revoke/expiry проверены end-to-end на реальном host, ошибочный credential не принимается, секреты не появляются в support bundle и upgrade сохраняет identity.

## M7. Reliability и наблюдаемость — P0

- Разобрать прежний FAIL на 941s: отделить истечение sampled UID из latest-100 от реальной задержки, auto-pause/scroll anchoring, query timeout/compaction и ingest retry.
- Сначала использовать короткие deterministic cases; сохранять UI revision/live/pause state, queue age, sequence, ACK/delivery и rotation timestamps, а не только итоговый assertion.
- Проверять создание event→durable spool→ACK→index→GUI и полный confirmed-event count; production-потери не определять по ограниченному GUI-окну.
- Добавить disk-full, WAL/manifest/segment interruption, corruption, retention, source rollover/vacuum, clock skew, network outage, service restart и upgrade tests.
- Измерять CPU/RSS/private/PSS, file descriptors, disk write amplification, oldest pending age и query latency. Resource growth от объёма базы не путать с утечкой.
- Длительный gate выбрать после коротких исправлений и отдельно согласовать с владельцем. Текущий план не разрешает снова запускать 30-minute/24/72-hour тест автоматически.

**Готово, когда:** причины старого сбоя установлены или получен достаточный диагностический reproduction; короткие invariants проходят; для production выполнен согласованный длительный gate с полной сверкой, без скрытой потери ACK events и необъяснённого роста ресурсов.

## M8. Безопасная поставка и платформенная матрица — P0 для public release

- **Выполнено 12.10.2026 для controlled Windows pilot:** административный per-machine installer, Program Files protection, installed-helper digest pin, UAC/effective-state audit checks (`ADMIN_INSTALL_AND_AUDIT.md`). Publisher signing/public release trust и перечисленные ниже gates остаются открытыми.
- Production signing core/desktop/helper/installer, защищённые release jobs и установка в защищённое место.
- Compile-time отключение unsigned dev helper path в production; verification publisher/signature между desktop/helper с сохранением allowlist/PID/path/UAC/snapshots.
- Rust advisory scan и SBOM; отдельно разобрать npm dev-tooling advisories и runtime exposure web/Worker. Не применять предлагаемые major downgrades без compatibility review.
- Зафиксировать минимальные Windows/Linux/macOS версии. Linux собирать на минимальной поддерживаемой ABI, проверить clean package install/uninstall/upgrade; добавить Linux clippy в CI.
- Актуальные macOS runtime/signing/notarization проверки. Windows remote physical validation и reboot/SCM lifecycle включить в release evidence.
- Versioned config/DB migrations, backup/restore и documented incompatible downgrade. Подписанные обновления и rollback добавлять после стабильного service/storage lifecycle.

**Готово, когда:** чистые поддерживаемые hosts запускают подписанную поставку без dev tooling, неподписанный/подменённый helper не принимается production desktop, обновление сохраняет state/identity и все обязательные advisory/reliability gates закрыты либо имеют документированное обоснованное решение.

**Внешние зависимости:** signing certificates/accounts, тестовые ОС/hosts, защищённое хранилище ключей. Секреты не включаются в план или исходники.

## M9. Более полная телеметрия и схема — P2

- Linux audit-file/netlink collector с rotation/checkpoint; bounded aggregation SYSCALL/EXECVE/CWD/PATH/PROCTITLE в единый event, partial/timeout diagnostics.
- eBPF — отдельный последующий источник при необходимости полного exec/file/network coverage; устанавливать только явно выбранным способом с понятными правами.
- macOS: сначала актуальная Unified Log validation/privacy diagnostics; Endpoint Security/OpenBSM — отдельный этап с entitlement/permission prerequisites.
- Typed timestamp/numeric/IP fields, исходная timezone, parser/source/schema version и сохранение original event. Process entity учитывать boot/start identity, не только повторно используемый PID.
- Показывать absent/redacted/not-applicable значения, не дорисовывать неизвестный parent/command line.

**Готово, когда:** согласованные события одинаково интерпретируются на всех заявленных ОС; exec aggregation/replay/rotation проходит fixtures и native cases; неполнота источника видна в GUI.

## M10. Аналитика, расследования и правила — P2

- Настоящий time range/timezone picker, numeric ranges/CIDR, field statistics/top values; histogram сообщает ограничения sampling.
- Related process/network/file timeline, sequence/absence/correlation, bounded rule state и replay.
- Пользовательские правила в валидируемом declarative формате без arbitrary code; versioning, test fixtures, suppression и explain/evidence.
- History/pinned filters, column widths, keyboard row navigation, focus/screen-reader UX. Виртуализация — при увеличении текущего UI-limit, с сохранением pinned details/live pause.
- Safe support bundle с preview/redaction и error codes; экспорт сохраняет redaction/CSV formula protections.

**Готово, когда:** правила воспроизводимы, bounded и не останавливают ingestion; расследование связано с реальными entities/events; keyboard/a11y и крупные результаты проходят реальные GUI tests.

## Следующие конкретные PR/коммиты

| Порядок | Небольшая единица работы | Зависимость / проверка |
|---|---|---|
| 1 — выполнено | Parser budgets + adversarial fixtures | `QUERY_LIMITS.md`; Windows/Linux unit и process API проверки |
| 2 | Linux bounded follow + metadata validation | M1; oversized lines и heartbeat host metadata |
| 3 | Query cancellation/concurrency/top-k | M1; timeout прекращает underlying работу |
| 4 | Retention age/cap + storage failure fixtures | M1; compaction/oversized single segment |
| 5 | Remote Windows/Linux pilot evidence | M2; доступный host/PKI от владельца |
| 6 | Service/daemon mode и local session auth | M3; close/reboot/crash/unknown listener |
| 7 | Durable agent spool и streaming delivery | M4; offline/force-kill/replay/lag |
| 8 | GUI onboarding/host health и credential rotation | M5–M6; real endpoint workflow |
| 9 | Production helper/signing и distro matrix | M8; signer/hosts prerequisites |

M7 instrumentation/failure checks сопровождают эти коммиты. M9–M10 следует начинать после устойчивого многомашинного контура, не выдавая дополнительные GUI-возможности за закрытие infrastructure gates.

## Общие критерии приёмки

- Проверять intended path целиком: endpoint → collector → durable storage → поиск/детекты → GUI.
- Не менять системные политики/службы/ACL/драйверы без явного разрешения на конкретное действие; текущие Sysmon/read ACL сохранить.
- Использовать временные базы и явно обозначенные fixtures для load tests. Не подмешивать demo events в рабочий контур.
- Secrets только в env/protected store, не в source/plan/logs; screenshots с реальными данными — локальные outputs.
- Rust fmt/tests/clippy, UI lint/typecheck/tests и затронутые native/end-to-end проверки; package rebuild — для итоговой поставки, не каждого UI edit.
- Каждая завершённая итерация обновляет evidence и readiness. Development commit не означает production tag/release; push выполняется только по отдельному запросу.

Связанные документы: `PRODUCTION_READINESS.md`, `PRODUCTION_ROADMAP.md`, `WINDOWS_AGENTS.md`, `LINUX.md`, `DESKTOP_RELEASE.md`, `VIEWS_AND_LOAD.md`.
