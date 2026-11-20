# Инструкция для coding agents RED//TRACE

Обновлено: 08.10.2026. Владелец явно возобновил Linux/WSL и запросил переработку фильтрации. Linux и проверки: `docs/LINUX.md`; общий contains и фильтры: `README.md`. Windows state/ограничения elevated операций ниже сохраняются.

Следующая согласованная итерация — GUI audit и события без ручного refresh — выполнена; текущие доказательства и follow-ups: `docs/GUI_AUDIT.md`. В ленте authenticated SSE, pause/resume, pinned event details, скрытые по умолчанию панели/график. Последние сборки NSIS 3.25 MiB и Linux `.deb` 5.30 MiB; Windows/Linux actual GUI live-проверки прошли.

Продолжение: сохранённые представления и выбор колонок реализованы и проверены в реальном Windows GUI; детали `docs/VIEWS_AND_LOAD.md`. Короткий burst PASS (5325/5325). Длинный runner завершился FAIL на 941s с GUI catch-up assertion; владелец отменил повтор длинного теста. Не заявлять успешный 30-minute soak; исходный отчёт `outputs/soak/report.json`, короткий `outputs/soak-short/report.json`.

Перед заявлением production readiness читать `docs/PRODUCTION_READINESS.md`: development source milestone не равен production release. Signing/helper trust, execution/storage/ingress budgets и reliability gates остаются открытыми; длинные тесты без нового указания владельца не повторять.

## Состояние проекта

12.10.2026: по явному указанию владельца SIEM установлен per-machine в Program Files и рекомендуемый Windows audit оставлен включённым после проверенного rollback/apply cycle. Используется installed helper без dev-env, protected ACL + pin, UAC. Канонический отчёт `docs/ADMIN_INSTALL_AND_AUDIT.md`; прошлое утверждение «audit policy/registry restored» ниже описывает старую итерацию. Не откатывать текущий audit как cleanup без нового указания.

RED//TRACE — локальный SIEM: Rust core, Tauri desktop/WebView UI, segment/WAL storage, Windows Event Log collectors и отдельные remote agents.

Уже реализовано и проверено на Windows:

- Нативный сбор System, Security, PowerShell Operational и Sysmon через EvtQuery, pull EvtSubscribe, EvtRender XML и bookmarks. `wevtutil` доступен как явный fallback `REDTRACE_WINDOWS_COLLECTOR=wevtutil`.
- Дедупликация Windows events с учётом EventRecordID; курсоры/UID разных remote agents изолированы.
- `redtrace-agent`: bounded outbox, retry, HTTPS/rustls с проверкой CA и SAN, WAL ACK, quarantine для недопустимых событий.
- Local agent management UI: регистрация, разовый показ токена, last_seen, отзыв.
- Dev Audit helper через защищённый Tauri IPC: allowlist, UAC, protected snapshots, apply/verify/selected rollback.
- Проверенный Microsoft Sysmon 15.22, подписанный Microsoft Windows Publisher, установлен и оставлен работающим.
- Текущему Windows-пользователю оставлены отдельные read-only ACE для Security и Sysmon. Исходные ACL сохранены в защищённом snapshot.
- Полные доказательства и оставшиеся release gates: `docs/WINDOWS_VALIDATION.md`.

Текущее состояние хоста — часть тестового окружения. Не удалять Sysmon и не откатывать ACL Security/Sysmon. Не менять audit policy/registry и не запускать elevated apply/restore без конкретного указания владельца. Уже подтверждено: audit policy и registry, изменённые тестом, восстановлены; Sysmon и read ACL намеренно оставлены.

## Обязательное поведение агента

1. Сначала прочитай этот файл и `docs/WINDOWS_VALIDATION.md`, затем проверь `git status`. Репозиторий может содержать крупные uncommitted/user changes: не очищай, не reset/rebase и не перезаписывай их.
2. Работай узкими итерациями. Перед изменением проверь конкретный маршрут/компонент и сформулируй проверяемый результат. Не запускай несколько конкурирующих Cargo/Tauri builds: они блокируют общий artifact lock.
3. Не запускай release/package rebuild после каждой CSS/TS правки. Сначала `npm run lint` и `npm exec -- tsc --noEmit`; release desktop/NSIS — один раз для итоговой проверки или когда действительно менялись Rust/Tauri/package resources.
4. Любое действие с UAC, auditpol, HKLM, Windows Event Log channel ACL, службами/драйверами требует явного подтверждения владельца в текущей задаче. Не считай прежнее разрешение бессрочным.
5. Sysmon сейчас должен остаться установленным и работающим. Security/Sysmon read ACL должны остаться выданными. Не выполняй удаление Sysmon и не запускай `Restore ACL` как cleanup.
6. Не скачивай и не устанавливай системные компоненты без отдельного разрешения. Sysmon был скачан с Microsoft и установлен с явным согласием; это не разрешение на другие драйверы или программы.
7. Не называй запуск UI успешным, пока проверены и core, и authenticated API, и число/наличие событий в самом UI. Проверяй parent PID sidecar и соответствие процесса порту 9710.
8. Core привязан к `127.0.0.1:9710`. Если порт занят, выясни PID/путь/parent. Не запускай новый desktop поверх старого core: предыдущий процесс с другим сессионным токеном приводил к 401 и пустому экрану. Корректно закрой desktop, дождись завершения его sidecar и только затем перезапускай.
9. Не оставляй orphan `redtrace.exe`, диагностические процессы или listeners. Не убивай процесс по одному имени, пока не проверены executable path, PID и parent.
10. При непредвиденном эффекте на системе остановись, сообщи точное состояние и восстанови только из соответствующего защищённого snapshot. Не маскируй rollback failure как успех.

## Обычные проверки

```powershell
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
npm run lint
npm exec -- tsc --noEmit
npm test
npm run desktop:ui:build
```

Windows end-to-end scripts:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-desktop-windows.ps1
node scripts\smoke-desktop-ui.mjs
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\smoke-installer-windows.ps1
```

`smoke-desktop-ui.mjs --audit-ui`, `--audit-all`, `--grant-log-read`, `--test-read-rollback`, `--recover-latest` вызывают реальные elevated операции/изменение ACL. Не запускать без явного согласия пользователя на конкретное действие. `--sysmon-leave <path>` устанавливает официальный pinned Sysmon; не выполнять повторно, поскольку Sysmon уже установлен.

## Приоритет продолжения

WAL recovery/rotation blocker закрыт 12.10.2026 (`docs/WAL_RECOVERY.md`). Рабочий core обновлён; source WAL/evidence и старый executable сохранены. Не очищать quarantine и не откатывать его байты в active WAL. Текущий installed GUI использует embedded frontend; Vite dev/hot reload доступен для разработки. Не собирать embedded desktop обычным Cargo без `tauri/custom-protocol` и не повторять setup ради каждого edit.

Актуальный план следующих работ: `docs/IMPLEMENTATION_PLAN.md`. При запросе продолжить разработку выбирать одну небольшую согласованную итерацию из его commit breakdown; не повторять уже реализованные TLS/native/GUI функции. Parser budgets реализованы и проверены (`docs/QUERY_LIMITS.md`); следующий code item — bounded Linux follow/ingest metadata, затем query/retention budgets. Сетевой пилот требует доступного endpoint/PKI; long tests и административные операции не разрешаются самим фактом существования плана.

Исторический Windows backlog предыдущей передачи (актуальный порядок определяется `docs/IMPLEMENTATION_PLAN.md`):

1. Добавить startup guard/понятную UI диагностику для stale API listener и ошибки session-token mismatch; не убивать неизвестный процесс автоматически.
2. Улучшить bounded resource profile WebView2/индекса, измеряя desktop process tree и отделяя WebView2 от Rust core/Sysmon.
3. Sysmon incomplete-install recovery, SCM identity и cleanup tests без удаления реально работающего пользовательского Sysmon.
4. Сохранить подписанный NSIS/helper как release gate; сертификат Authenticode недоступен — dev binaries unsigned.
5. Отдельный remote Windows endpoint, reboot/sleep/channel rollover, 24/72-hour soak и rate limits.

Windows-приоритеты выше описывают предыдущую передачу; их порядок уточнён в `docs/IMPLEMENTATION_PLAN.md`. Результаты выполненных итераций находятся в `docs/LINUX.md`, `docs/GUI_AUDIT.md`, `docs/VIEWS_AND_LOAD.md`. Новые системные установки/привилегированные изменения по-прежнему требуют отдельного согласования.

## Ожидаемый отчёт

В конце сообщи: что изменено, какие команды/проверки прошли, фактическое число событий и процессные ресурсы с методом измерения, состояние Sysmon/ACL, путь к собранному артефакту и оставшиеся точные блокеры. Не сообщай «готово», если проверены лишь compilation/unit tests.
