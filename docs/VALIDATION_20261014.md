# REDTRACE 0.2.0 — результат завершения разработки

Дата отчёта: 14 октября 2026. Реализация началась 13 октября; результаты и пакеты находятся в `outputs/development-20261013`.

## Реализовано

Общая versioned конфигурация и профили, источники и include/exclude DSL, Linux audit file aggregation, macOS native Endpoint Security helper и явный eslogger backend, одноразовый enrollment с локальной CA, user/system service provisioning, fleet health и remote desired config. Добавлены продление/смена сертификатов, hot reload токена, восстановление автоматической credential после потери ответа, пользовательские правила/replay/fixtures/versioning/suppression, cases, потоковый backup/inspect/restore и compatibility markers. NDJSON contract для отдельного будущего NTA уже подключается к общему ingestion.

Инструкция: [SETUP_AND_OPERATIONS.md](SETUP_AND_OPERATIONS.md). Подробности исправлений: [DEVELOPMENT_20261013.md](DEVELOPMENT_20261013.md).

## Проверки

| Проверка | Результат |
|---|---|
| `cargo test --all-targets` на macOS arm64 | 246 passed, 0 failed |
| Core `cargo clippy --all-targets -- -D warnings` | PASS |
| Core/desktop `cargo fmt --check` | PASS |
| ESLint и `tsc --noEmit` | PASS |
| Web build и Node UI tests | PASS, 17 tests |
| Desktop UI build / macOS `.app` build | PASS |
| Windows GNU и Linux GNU `cargo check --all-targets` | PASS, cross-check на macOS |
| Windows x64 / Linux x64 release CLI/agent binaries | PASS, cross-build; native execution ещё не проверен |
| HTTPS enrollment → desired config → event/rule/replay → CA prepare/ack/activate → backup/restore → restart | PASS, временные fixtures |
| Потерянный automatic-token reply и повтор после restart | PASS, тот же credential без plaintext token в registry |
| Backup maintenance gate при heartbeat / checksum / corrupted staging / future-format refusal | PASS |
| Audit interleaved groups/rotation/UTF-8, ES normalization и optional-source budgets/fairness | PASS |
| macOS GUI window, реальные WebView health/search/live requests, API 401, GUI quit/core cleanup | PASS |

В native macOS smoke с lookback 2 минуты доступных событий было **0**. Источник устойчиво перешёл в `streaming`, `last_error=null`; новая доставка реального security event этой проверкой не подтверждена. Синтетические данные в рабочий интерфейс не подмешивались.

Короткий замер Basic core: 8 macOS `ps` samples, отдельная временная база, lookback 2 минуты, 0 событий. После startup RSS составил примерно **10.1–10.4 MiB**, CPU **0–0.1%**. Первый sample получен до полного запуска и не используется для оценки памяти. WebKit/XPC процессы не входят в этот замер. Это idle/startup sample, без заявления capacity/EPS/soak.

## Поставка

`REDTRACE-0.2.0-macos-arm64.tar.gz` содержит `.app`, core и CLI/agent/service binaries с инструкцией. Ad-hoc signature проверена `codesign --verify --deep --strict` до архивирования. Архив собирается вне macOS File Provider folder, чтобы Finder metadata не нарушала проверку подписи. Developer ID/notarization не выполнялись.

`REDTRACE-0.2.0-source.zip` содержит текущие исходники/config/tests/docs без dependency caches, собранных бинарников, рабочих logs/data/credentials. `.git` в исходном workspace отсутствует; revision не выдумывается. SHA-256 артефактов записан в `manifest.json`.

Windows/Linux CLI/agent комплекты cross-built и описаны в manifest отдельно. Их native execution, SCM/systemd installation/reboot и GUI installers этой итерацией не подтверждены. macOS GUI-проверка не распространяется на Windows/Linux.

`REDTRACE-0.2.0-windows-x64-cli.zip` содержит Windows GNU core/agent/admin/service binaries и audit helper, без GUI installer. PE imports проверены: MinGW runtime DLL в зависимостях нет, остаются Windows/UCRT libraries. `REDTRACE-0.2.0-linux-x64-cli.tar.gz` содержит Linux GNU core/agent/admin/service binaries без GTK/WebKit; максимальная required GLIBC version по всем бинарникам — **2.28**. Полный вывод зависимостей сохранён в `binary-dependencies.json`. Эти проверки структуры бинарника не заменяют native smoke.

## Открытые проверки

Native auditd telemetry и реальный ES stream с root/FDA/Apple entitlement, новые Windows/Linux native install/reboot/GUI tests и длительная сохранность остаются отдельными проверками на соответствующих хостах. Системные политики, Sysmon/ACL и существующие службы не изменялись. Длительный soak не запускался.

NTA producer пока не реализован; готов interface/reader. Backup остаётся приватным незашифрованным архивом. v1 migration сохраняет текущие storage formats и отказывает при неизвестной будущей версии; automatic updater не добавлялся. Исходные beta-пакеты `outputs/beta-20261013` сохранены отдельно.
