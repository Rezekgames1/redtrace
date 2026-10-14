# RED//TRACE — передача разработки на Windows

## Административная установка и аудит — 12.10.2026

Установлен per-machine NSIS в `C:\Program Files\REDTRACE`, protected Administrators/System owner/DACL + Users RX, helper digest pin вместо dev-env gate. Installed ordinary GUI + UAC helper прошёл native baseline/apply/rollback equality для четырёх настроек и реальные 4688/4104. Рекомендуемый аудит оставлен включённым по запросу владельца; snapshot возврата `4f740ebe26568ca844e588f5aed5b691`. Sysmon/read ACL сохранены. 85 Windows Rust tests, fmt/core+desktop clippy, TS/targeted lint проходят; подробности и точные границы проверки `docs/ADMIN_INSTALL_AND_AUDIT.md`. Snapshot IDs/PKI/data остаются в protected stores; source commit не содержит рабочих credentials или журналов.

## M1: query parser budgets — 08.10.2026

Реализованы ограничения UTF-8 bytes/tokens/вложенности/AST nodes до и во время разбора, общий depth budget скобок/NOT, корректные byte offsets и fail-closed настройки. Search/aggregations/export используют общий ограниченный parser; health/diagnostics показывают действующие лимиты. Windows 74 и Linux 68 Rust tests прошли, включая process API fixtures; Windows core/desktop clippy, UI lint/typecheck/build/9 tests прошли. Linux clippy по-прежнему не установлен. Подробности и статус поставки: `docs/QUERY_LIMITS.md`. Следующий пункт плана — bounded Linux follow и ingest metadata. Изменения этой итерации ещё не закоммичены.

## Обновление 08.10.2026

GUI/live-итерация завершена: `docs/GUI_AUDIT.md`. SSE после durable indexing, авто-reconnect/resync, pause/resume и удержание деталей, разгруженные workspace. Windows Sysmon→WebView 795–1365 ms, Linux journald→WebKit 938–1134 ms в отдельных замерах; 66 Windows/60 Linux Rust tests. NSIS 3.25 MiB, `.deb` 5.30 MiB пересобраны. Sysmon/ACL сохранены, elevated действий не было.

Владелец возобновил Linux и запросил новые фильтры. Реализованы общий contains по всем значениям, exact/contains/existence по полям, исключения и рабочий UI-конструктор. Подтверждены Windows WebView filters и обновлённый NSIS. Linux collector расширен на весь доступный journal, bounded backfill, cursor-based UID/recovery, SSH/sudo/audit context; core/agent и crash/retry smoke прошли. После явного разрешения установлен Linux build toolchain GTK/WebKit/Node; собран `outputs/linux/REDTRACE_0.1.0_amd64.deb` (5.30 MiB), настоящий WSLg GTK/WebKit UI показал 100 реальных Linux строк. Подробности, ограничения и resource snapshot: `docs/LINUX.md`, `docs/WINDOWS_VALIDATION.md`. Указания о приостановке Linux в исходном handoff ниже — исторические.

## Обновление Windows-этапа — 07.10.2026

Инструкции следующему coding agent: `docs/AGENT_GUIDE.md`. Актуальная проверка: `docs/WINDOWS_VALIDATION.md`. Ниже сохранён исходный handoff от 03.10.2026; его пункты «ещё не реализовано» следует читать с учётом этого обновления.

- Нативный Windows Event Log collector реализован: EvtQuery/pull EvtSubscribe, XML bookmarks, System/Security/PowerShell/Sysmon; wevtutil оставлен явным fallback.
- Remote agents реализованы: HTTPS с проверкой сертификата, per-agent UID, ACK после WAL, retry/quarantine, UI tokens/last_seen/revocation.
- Windows dev audit helper реализован, доступен только через Tauri IPC при REDTRACE_AUDIT_DEV=1. Владелец разрешил unsigned dev-build и реальные apply/rollback на текущем хосте. Добавлены verified Sysmon preview/install и current-user read-only channel ACL операции.
- Проверен UAC apply/verify/rollback всех четырёх audit/registry действий; исходные значения восстановлены. Snapshots administrator/SYSTEM-only; rollback selected-only, с conflict detection и recovery после потерянного ответа.
- 60 Rust tests, clippy core/desktop, UI lint/typecheck/build, real native logs, separate core/agent TLS, crash recovery, actual WebView agent/Audit/Sysmon/read-ACL UI, single-instance и sidecar lifecycle прошли.
- Unsigned NSIS-пакет с core/helper собран, установлен во временный каталог, проверен и удалён.
- Microsoft Sysmon 15.22 проверен и установлен через UI/UAC, оставлен по выбору владельца. Текущему пользователю выданы только read-ACE на Security/Sysmon; restore/re-grant и effective normal-user read проверены. Подтверждён live native Sysmon ProcessCreate с PID/PPID/command line.
- Остались production gates: Authenticode, Sysmon lifecycle/recovery на других версиях, reboot/rollover/soak, rate limits и отдельная remote Windows validation. Linux-этап приостановлен владельцем.

Дата среза: 2026-10-03. Проект переносится на Windows-хост для нативной проверки и продолжения разработки. Архив содержит исходники и конфигурации, но не содержит `node_modules`, Rust `target`, собранных sidecar-бинарников, локальных журналов пользователя, `.env` и ключей подписи.

## Главные требования владельца

- Это лёгкий локальный SIEM для Windows, Linux и macOS.
- Никакого Elasticsearch/JVM и никаких демонстрационных событий в рабочем контуре.
- Интерфейс показывает только реальные журналы текущего хоста.
- Обязательные поля: `event.description`, `process.command_line`, `process.pid`, `process.parent.pid`.
- API слушает только loopback. Desktop-режим дополнительно требует случайный сессионный токен.
- Настройка Windows Audit и Sysmon не должна выполняться скрытно: только preview, явное подтверждение, snapshot, verify и rollback.
- Не публиковать проект и не отправлять логи наружу без отдельного указания владельца.

## Что уже реализовано

- Rust core, bounded ingestion queue, WAL с checksum/fsync, immutable JSONL segments, atomic manifest, compaction и retention.
- Собственный DSL: поля, фразы, `AND`, `OR`, `NOT`, скобки и prefix `*`.
- Дисковые dictionaries/postings, delta-varint, offsets v3 для прямого `seek`, bounded cache четырёх индексов.
- Cursor pagination, aggregations и лимиты сложности/времени запросов.
- Durable checkpoints: macOS timestamp, Linux journald cursor, Windows EventRecordID.
- Windows collector читает реальные Security, PowerShell Operational и Sysmon через `wevtutil.exe`; PowerShell для сбора не требуется. Это пока polling, а не production subscription.
- Базовые детекты: brute force, Event 4740, PowerShell 4104, suspicious command line, отказ `sudo`.
- Durable alert log с checksum, suppression и лимитом размера.
- Серверный JSON/JSONL/CSV export с redaction и защитой от CSV formula injection.
- UI: события, алерты, источники, Windows Audit preview и безопасная диагностика.
- Tauri/Wry desktop shell, single-instance, sidecar lifecycle, CSP и 256-битный API token.
- CI matrix для macOS, Windows и Linux в `.github/workflows/desktop.yml`.

Локальные результаты на macOS перед передачей:

- 32 Rust unit/integration tests;
- clippy без предупреждений;
- UI lint/build/render test;
- crash recovery на копии реальной базы: 65 → 65 событий;
- 500 поисков, concurrency 20: p95 около 11 мс, RSS core около 12 МБ;
- release desktop shell около 56 МБ плюс core около 8 МБ.

## Подготовка Windows-хоста

Установить:

1. Git.
2. Node.js 24 LTS и npm.
3. Rust stable через `rustup` с target `x86_64-pc-windows-msvc`.
4. Visual Studio Build Tools 2022: workload «Desktop development with C++», Windows SDK.
5. Microsoft Edge WebView2 Runtime.

Распаковать ZIP в обычный пользовательский каталог без OneDrive-синхронизации. В PowerShell из корня проекта:

```powershell
rustup default stable-x86_64-pc-windows-msvc
npm ci
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
npm run lint
npm test
npm run desktop:ui:build
cargo check --manifest-path src-tauri/Cargo.toml
```

Нельзя исправлять ошибки удалением lock-файлов или заменой архитектуры. Сначала зафиксировать точный вывод и причину платформенного расхождения.

## Первый реальный запуск на Windows

Терминал 1, по возможности сначала без повышения прав:

```powershell
$env:RUST_LOG = "redtrace=info"
cargo run --release
```

Терминал 2:

```powershell
npm run dev
```

Открыть `http://localhost:3000`. Проверить `/api/health`, затем UI «Источники». Если Security log недоступен без администратора, это должно отображаться как понятная ошибка разрешений, а не заменяться тестовыми данными.

Проверить реальные запросы:

```text
event.id:4624
event.id:4625
event.id:4688
event.id:4740
event.id:4104
source:windows.sysmon
process.command_line:*
```

Для Sysmon использовать только официально установленный/проверенный Sysmon. Не скачивать и не устанавливать драйвер автоматически.

## Проверка desktop-сборки

```powershell
npm run desktop:build -- --no-bundle
npx tauri build --config src-tauri/tauri.conf.json --bundles nsis --ci --no-sign
```

Проверить:

- появляется одно окно, повторный запуск не создаёт второй экземпляр;
- sidecar `redtrace.exe` запускается дочерним процессом и завершается вместе с окном;
- запрос к `http://127.0.0.1:9710/api/health` без токена в desktop-режиме получает `401`;
- UI получает реальные события через Tauri token command;
- после reboot/sleep журнал продолжается с EventRecordID без массовых дублей;
- установщик не требует Node.js или Rust на пользовательской машине.

## Приоритет следующего агента

### P0 — нативный Windows Event Log

Заменить `wevtutil` polling на Windows Event Log API:

- `EvtSubscribe` для Security, PowerShell Operational и Sysmon;
- durable bookmark через `EvtCreateBookmark`, `EvtUpdateBookmark`, `EvtRender`;
- корректный XML render, EventRecordID, channel rollover и reboot recovery;
- bounded callback queue: callback не должен парсить/писать на диск;
- понятная диагностика access denied и отсутствующего канала;
- сохранить текущий `wevtutil` collector как явный fallback до стабилизации native path;
- добавить Windows fixture и integration tests, не добавляя runtime demo events.

Рекомендуется target-specific dependency `windows-sys` или `windows`, ограниченная `cfg(target_os = "windows")`. Не ломать сборку macOS/Linux.

### P0 — Windows Audit privileged helper

Транзакционное ядро уже находится в `src/audit/windows.rs`. Нужен отдельный минимальный подписываемый helper:

- UAC только при фактическом apply/rollback;
- запрос содержит только allowlisted action IDs, без произвольной команды;
- `auditpol /backup`, точечный registry snapshot, apply, reread/verify;
- rollback при первой ошибке;
- Sysmon: WinVerifyTrust/Authenticode, проверка Microsoft publisher и показ SHA-256;
- IPC только с desktop shell, не HTTP route;
- журнал действий без содержимого пользовательских событий.

До реализации и проверки helper `/api/audit/windows/status` обязан возвращать `executor_available: false`.

### P1

- 24/72-часовой soak на Windows с измерением RSS, CPU, dropped/duplicate events и роста диска.
- Проверка crash/restart и повреждения WAL/segment на NTFS.
- Подписанный NSIS/MSI, Authenticode и защищённый auto-update.
- Golden fixtures для разных Windows build/channel configurations.

## Важные файлы

- `src/main.rs` — API, ingestion, auth и endpoints.
- `src/collector/windows.rs` — текущий Windows collector/fallback.
- `src/storage/` — WAL, checkpoints, segments, postings и offsets.
- `src/detection.rs` — rules и alert log.
- `src/audit/windows.rs` — audit plan и transaction core.
- `app/page.tsx`, `app/operations.tsx`, `app/events/` — UI и API client.
- `src-tauri/` — desktop shell.
- `scripts/prepare-sidecar.mjs` — target-specific sidecar.
- `docs/PRODUCTION_ROADMAP.md` — полный production backlog.
- `docs/DESKTOP_RELEASE.md` — правила desktop release.

## Definition of done для Windows-этапа

Этап нельзя считать завершённым только потому, что код компилируется. Нужны доказательства на реальном Windows-хосте:

- real Security/PowerShell/Sysmon events видны после restart и reboot;
- bookmark не теряет подтверждённые события и не создаёт неограниченные дубли;
- API token, single-instance и sidecar lifecycle работают в установленной сборке;
- audit apply имеет snapshot/verify/rollback и не принимает произвольные команды;
- тесты, clippy, UI build и Windows installer проходят;
- в рабочем интерфейсе нет demo fixtures или сгенерированных событий.
