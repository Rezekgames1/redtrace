# Production readiness — 08.10.2026

## Вердикт

Обновление 21.10.2026: текущая 0.2.0 остаётся контролируемым пилотом. Исправлен шум activity-записей macOS Unified Log и разбор/отображение прав authd; обновлённая сборка установлена на Mac, новые реальные события проверены в API и нативном GUI. Прошли 257 Rust-тестов и 20 UI-тестов. Endpoint Security в рабочей конфигурации выключен; полное процессное/файловое покрытие и native sudo-command probe не подтверждены. Windows-ноутбук выключен владельцем, обратная GUI-проверка доставки остаётся открытой. Подробности: [macOS telemetry](MACOS_TELEMETRY_20261021.md).

Обновление 13.10.2026: выдана **ранняя beta 0.1.0 / build 2026-10-13** с Windows GUI installer и Windows/Linux/macOS CLI+agent packages в `outputs/beta-20261013/`. Query/ingest budgets, bounded Linux reader, retention age/cap, durable spool, service source implementation и critical ACK/checkpoint/detection исправления реализованы. Добавлена фильтрация даты/времени. Прямой Windows↔MacBook LAN HTTPS, restart и offline/force-kill recovery проверены. Актуальные инструкции: `BETA_INSTALL.md`; evidence: `BETA_VALIDATION_20261013.md`. Перечисленные ниже старые implementation gaps — исторический срез; publisher signing, unattended platform boot/upgrade и согласованный длительный reliability gate остаются будущими production gates. Security reviews при подготовке итоговой beta остановлены по прямому указанию владельца.

Обновление administrative deployment 12.10.2026: per-machine UAC installation / protected Program Files / helper digest pin реализованы, dev-env requirement устранён для installed mode, actual four-setting audit apply/verify/rollback и 4688/4104 live прошли (`ADMIN_INSTALL_AND_AUDIT.md`). Authenticode publisher signing остаётся открытым gate; старые dev-helper замечания ниже относятся к прежнему механизму.

Обновление 12.10.2026: конкретный WAL corruption/replay/rotation defect исправлен (`WAL_RECOVERY.md`): 15 175 UIDs сохранены на real-data working copy, 1000 ACK fixtures восстановлены после crash/rotation, current working DB diagnostics — 0 corrupted/IO errors с сохранённой quarantine history. Это закрывает данный runtime blocker, не остальные production gates. Current Rust checks — 83 Windows / 77 Linux tests.

Исторический срез 09.10.2026: базовый Windows/Kali WSL контур и query suggestions проверены в настоящем GUI (`BASIC_STATUS_AND_FILTERS.md`). Тогда был открыт runtime storage defect: 1 corrupted WAL record, rotation skipped / segment errors. Он закрыт обновлением 12.10 выше. Состояние storage нельзя считать чистым по одному counter `wal_errors=0`.

**Закрытая alpha / контролируемый read-only пилот. Production-релиз с гарантией 24/7, сохранности всех событий под нагрузкой и безопасной поставки пока не подтверждён.**

Windows native collection, Linux journald, TLS agents, WAL/index recovery, реальные GUI/live-проверки и настройки представлений существенно развиты относительно первоначального прототипа. Эта оценка отражает текущую реализацию; старые пункты roadmap о `wevtutil` как основном пути или отсутствии desktop устарели.

| Сценарий | Пригодность |
|---|---|
| Локальный обозреватель/поиск на собственном Windows-хосте, read-only | Подходит для контролируемого использования с резервной копией данных и наблюдением за health |
| Закрытый Windows/Linux пилот на проверенных конфигурациях | Условно подходит; не использовать как единственный источник гарантированного мониторинга |
| Корпоративный SIEM 24/7, unattended/security-critical | Не готов: release gates ниже не закрыты |
| Публичный agent-ingest | Не рекомендуется до aggregate/per-agent resource limits и управления сертификатами |
| Публичный web/Worker deployment | Отдельно не прошёл production security assessment; devDependency classification не доказывает отсутствие runtime exposure |
| Универсальная кроссплатформенная поставка | Не подтверждена: Kali build не доказывает совместимость старых дистрибутивов, текущий macOS runtime не проверялся |

## Что подтверждено

GUI beta delivery 13.10.2026: актуальные Linux `.deb` и macOS arm64 `.dmg` добавлены к Windows installer. Native Linux GTK/WebKit и macOS onscreen GUI/core smoke PASS; инструкции — `BETA_INSTALL.md`, evidence — `BETA_VALIDATION_20261013.md`. Cross-distro minimum ABI, Intel Mac, publisher signing/notarization и native boot/upgrade gates отдельно не закрыты.

- 74 Windows / 68 Linux Rust tests после parser-budget итерации; Windows core/desktop clippy и fmt. Отчёт: `docs/QUERY_LIMITS.md`.
- 9 Node UI/validation/render tests, ESLint, TypeScript, web/desktop builds.
- Реальные Windows Sysmon и Linux journald → authenticated SSE → GUI без manual collect.
- Pause/resume, pinned details, network recovery, workspace catch-up; реальные GUI saved views/columns/reload checks на Windows.
- Loopback API token; remote HTTPS/rustls, CA/SAN checks, per-agent UID, ACK после WAL и retry/quarantine.
- Crash/restart и TLS/ingress проверки предыдущих итераций; короткий burst 5325/5325 без retry, duplicate replay без дополнительных записей.
- Защищённый Windows audit helper boundary с allowlist/PID/path checks, snapshots и UAC; операции этой оценки были read-only.

Доказательства: `docs/WINDOWS_VALIDATION.md`, `docs/LINUX.md`, `docs/GUI_AUDIT.md`, `docs/VIEWS_AND_LOAD.md`. Это не независимая сертификация и не доказательство всех power-loss/disk-full/reboot случаев.

## Обязательные блокеры перед production

### 1. Надёжность и режим работы

- Длинный runner завершился FAIL на 941s: 22675 fixtures отправлено, 5 retry, GUI catch-up assertion не прошёл. Финальная сверка всех записей не выполнена. Изменение sampler-критерия не доказывает причину старого сбоя; повтор долгого теста отменён владельцем (`docs/VIEWS_AND_LOAD.md:53–57`).
- Reboot/sleep/channel rollover/journal vacuum, disk-full/retention/high-cardinality и отдельный физический remote endpoint не закрыты текущими GUI-проверками.
- Desktop завершает core при закрытии окна (`src-tauri/src/main.rs:73–83`). Это ожидаемая текущая архитектура, но не постоянно работающий unattended sensor. Нужен независимый service/daemon lifecycle и recovery, если обещается 24/7.

### 2. Подписанная поставка и privileged helper

- Текущий NSIS/helper unsigned. В release-коде dev helper включается через `REDTRACE_AUDIT_DEV=1` и наличие файла (`src-tauri/src/audit.rs:68–82`, `131–164`).
- Elevated helper проверяет PID/path desktop, но эта проверка не заменяет publisher/signature trust (`src/audit/helper.rs:900–920`). Это не установленный silent-elevation exploit: UAC и явные allowlisted запросы сохраняются.
- Для production нужны подписанные binaries/installer, защищённое место установки, publisher verification и невозможность случайно включить unsigned dev-path в production-сборке. Sysmon signature verification отдельно не подписывает REDTRACE.

### 3. Resource/input budgets — подтверждённые статическим review пробелы

Следующие исходные пункты классифицированы как MEDIUM. Они не воспроизводились как crash/exploit в исходной оценке и не являются подтверждёнными новыми HIGH-блокерами для development commit. Parser-budget пункт закрыт последующей итерацией; остальные остаются открытыми.

| Область | Наблюдение и влияние | Приоритет исправления |
|---|---|---|
| Query parser — закрыто | Введены bytes/tokens/depth/nodes budgets до/во время parse; скобки и `NOT` ограничены до рекурсии, AST nodes резервируются до построения. Все три query API используют общий parser; adversarial/boundary/process fixtures прошли на Windows/Linux | `QUERY_LIMITS.md`; execution/cancellation budgets остаются отдельной задачей |
| Search executor | Disk search материализует все совпавшие events до truncate; timeout `spawn_blocking` не отменяет работу; repeated set unions в contains/existence увеличивают стоимость (`src/storage/segments.rs:230–260`, `src/main.rs:877–900`, `src/index.rs:112–124`, `src/storage/segment_index.rs:233–245`) | Bounded top-k/pagination, cancellation/deadlines, query concurrency limit, in-place postings accumulation |
| Ingest | Лимиты body/batch/queue существуют, но нет aggregate/per-agent concurrency/byte-rate budget; heartbeat `host.os` сохраняется без bounded platform validation (`src/ingest.rs:279–284`, `528–539`, `609–639`, `671–687`) | Validate metadata, per-agent/global quotas, bounded waiting и throttled logs |
| Retention | Oversized sole segment не удаляется; compaction обновляет `created_unix`, а time retention использует возраст сегмента (`src/storage/segments.rs:163–177`, `291–309`, `334`, `373–386`) | Сохранить age boundaries, split output segments, enforce hard cap policy |
| Linux follow | Backfill ограничен по размеру записи, live `lines().next_line()` не имеет того же explicit cap (`src/collector/linux.rs:103–114`, `214–216`) | Bounded live reader и oversized-event diagnostics |

### 4. Платформы и полнота телеметрии

- Linux `.deb` собран на Kali rolling, проверен через извлечение и настоящий WSLg WebKit. Минимальная поддерживаемая distro/ABI и system package install требуют отдельного gate.
- Linux собирает journald; отдельный audit file/netlink/eBPF, полный exec aggregation не реализованы. Нельзя обещать полное покрытие каждого запуска процесса.
- macOS Unified Log существует, но новый macOS GUI/runtime, signing/notarization и расширенный Endpoint Security coverage в этой сессии не проверены.
- Встроенный ruleset ограничен; production detection coverage, пользовательские правила, sequence/absence/replay и tuning требуют отдельных критериев.

## Dependencies и commit hygiene

- `npm audit --omit=dev --json`: **0 vulnerabilities**.
- Полный npm audit: **7 HIGH propagated entries** от braces (`GHSA-vfj7-8cjw-p6xm`) и **4 MODERATE** в Drizzle/esbuild tooling. Это не семь независимо доказанных HIGH-уязвимостей desktop приложения.
- Desktop собирается отдельным Vite React config (`vite.desktop.config.ts:1–15`) и включает static assets, а core/helper — Rust binaries. Reachability указанной glob/build chain в packaged desktop не установлена; exhaustive bundle audit не выполнялся.
- Web/dev scripts запускают vinext, Worker импортирует vinext server: public web deployment нельзя объявлять безопасным только по `--omit=dev`. Request-to-vulnerable-operation exploit path здесь не подтверждён.
- Автоматические npm предложения — major downgrades, не доказанный совместимый patched upgrade; зависимости в этой оценке не изменялись.
- `cargo-audit` не установлен. Rust advisory clearance/SBOM не подтверждены; инструменты не устанавливались.
- Сканирование секретных patterns и проверка diff не выявили реальных ключей/токенов в предполагаемом commit scope. Это не формальный exhaustive secrets audit.
- `outputs/`, binaries, build directories, `.env*` и PEM исключены из Git. Скриншоты/локальные журналы и результаты нагрузки не добавляются в source commit.

## Рекомендуемый следующий release milestone

Подробный implementation backlog с состоянием уже реализованного, зависимостями и acceptance: `docs/IMPLEMENTATION_PLAN.md`.

1. Закрыть query/ingress/retention budgets и ограничить Linux follow records.
2. Разобрать прежний long-run failure и получить согласованный reliability gate; до нового разрешения длинные тесты не повторять.
3. Ввести production signing/helper trust и unattended collector lifecycle.
4. Проверить реальную минимальную Linux distribution и актуальный macOS release, затем оформлять public beta.

Коммит текущей версии допустим как development milestone; tagging/publishing production release не выполняется.
