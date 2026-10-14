# Реализация обязательных возможностей

Цель: лёгкий локальный SIEM для Windows, Linux и macOS; простой запуск collector и подключение агентов; управляемые источники, фильтрация и правила; модульный контракт для последующего NTA.

Работы текущей задачи:

- [x] Общая versioned конфигурация, Basic/Extended/Custom, каталог модулей и нормализованные поля; Linux audit path валидируется независимо от ОС, на которой создаётся пакет.
- [x] Linux audit file reader: bounded aggregation SYSCALL/EXECVE/CWD/PATH/PROCTITLE/EOE, interleaved frontier, numeric rotation и durable checkpoints.
- [x] macOS native Endpoint Security helper, явный eslogger compatibility backend, нормализация exec/file/auth/exit, диагностика прав и dropped records.
- [x] Одноразовый enrollment-пакет, локальная PKI, настройка HTTPS collector, установка при входе и отдельная системная установка на трёх ОС.
- [x] Fleet health: backlog/bytes/age/retry/quarantine/permissions/lag/liveness; настройки конкретного агента читаются и применяются через heartbeat.
- [x] Certificate hot reload/renewal, двухэтапная CA rotation с durable trust acknowledgement, token hot reload и повторная доставка автоматической credential после потерянного ответа/рестарта.
- [x] Пользовательские правила: versioning, conditions, threshold/sequence/absence, exceptions/suppression, fixtures/replay и cases.
- [x] Потоковый backup/inspect/restore, checksums, приватный staging, совместимость v1/legacy и отказ от будущих версий до изменения базы; restore в новый каталог для rollback.
- [x] Интеграция UI/API/CLI и инструкция [SETUP_AND_OPERATIONS.md](SETUP_AND_OPERATIONS.md).

Расширенные источники включаются явно. Очереди и обработка ограничены по records/bytes/work; базовый режим не запускает audit/ES/NTA. Системные политики не меняются при обычном старте. Административная установка выполняется только отдельным действием пользователя. Существующие базы, установленные сенсоры и политики не используются для destructive проверок.

CI и публикация не входят в задачу. NTA-модуль планируется после SIEM; в этой задаче реализуется его интерфейс подключения.

## Завершение после переноса контекста

Исправлены общий optional-source budget и fair progress, cumulative module health, valid-prefix recovery malformed inputs, UTF-8 audit argv fragments, ES variants и обработка очереди после выхода helper. Фильтры компилируются при изменении настроек. Устранены concurrent config/PKI updates, отсутствующее автопродление после первого live setup, CORS PUT, частичное применение agent batch limits и перезапись trust существующего агента при повторном enrollment.

Backup удерживает общий maintenance gate с ingress heartbeat/registry mutations; worker владеет guards и после отмены HTTP-запроса. Rule replay учитывает UTC offsets/равные timestamp; state accounting включает overhead, переполнение generations и возврат старой revision отклоняются. Исправлена коллизия test-каталогов от недостаточной точности clock: каждый query fixture получает случайный ID.

Native macOS smoke дополнительно обнаружил служебный текст `Filtering the log data using ...` перед NDJSON: reader теперь пропускает известный preamble и пустые строки, продолжая отклонять неизвестные повреждённые записи. WAL process test изолирован от локального collection, использует отдельный API port и повторяет идентичный batch при предусмотренном контрактом HTTP 429; durable UID equality после crash/replay сохранена.

Проверки включают полный Rust suite, core clippy/fmt, TS/ESLint, 17 UI tests и web/desktop builds; Linux и Windows — cross-check исходников на macOS. Сквозной process fixture проверяет HTTPS enrollment, desired config, скрытие исключённых событий, правило/replay, CA trust overlap и блокировку переключения для неподтвердившего агента, backup/restore и restart. Новые regression suites: `tests/telemetry_sources.rs`, `tests/rules_backup_reliability.rs`, расширенные `product_features`, `control_process`, `ingest`.

## Точные границы

Реальный ES stream с root/FDA/Apple entitlement и новые auditd правила не включались. Native installation/reboot системных служб на Windows/Linux и новые кроссплатформенные GUI-пакеты не проверены на физических хостах в этой итерации. Длительный soak не выполнялся. NTA producer не реализован: готов bounded NDJSON contract/reader. Backup приватный, без шифрования. Миграция сохраняет текущий v1 storage, а не обещает чтение будущих несовместимых форматов. Старые beta artifacts не заменялись.
