# Windows dev validation — 07.10.2026

## Административная поставка — 12.10.2026

Installed audit теперь доступен без dev-env: per-machine NSIS, Program Files owner/DACL protection, helper digest pin. Настоящий installed GUI прошёл effective baseline/apply/rollback/final checks, реальные 4688/4104 поступили после исправления native subscription signal/drain. Четыре audit settings оставлены включёнными по запросу владельца, protected rollback snapshot сохранён; Sysmon/read ACL остаются активными. Подробности: `ADMIN_INSTALL_AND_AUDIT.md`. Старые dev-only инструкции ниже исторические.

## Обновление 08.10.2026 — поиск и Linux

Последующая итерация GUI/live: `docs/GUI_AUDIT.md`. 66 Rust tests; authenticated SSE, фактический Sysmon→WebView без manual collect, pause/resume/pinned details/network recovery и workspace catch-up прошли. Новый NSIS — 3.25 MiB. Поля/детали/график скрыты по умолчанию, 1440/1024 layout проверен без overflow; снимки других workspace проверены read-only, UAC/ACL/службы не менялись.

- Общий contains по всем значениям, exact/contains/existence по полю, исключение и UI-конструктор фильтров; единые результаты RAM/disk, экранирование и сохранение OR-precedence.
- Windows Rust tests: 65 passed; core и desktop clippy, fmt, UI lint/typecheck, web/render tests и desktop build прошли.
- Реальная WebView-проверка `node scripts/smoke-desktop-ui.mjs --filters`: общий contains по source и точный source-filter через конструктор; 100 реальных windows.sysmon строк в UI. Регистрация/показ/скрытие/отзыв токена также прошли.
- Пересобран unsigned NSIS: `src-tauri/target/release/bundle/nsis/REDTRACE_0.1.0_x64-setup.exe`, 3.24 MiB. Установка/удаление этой новой сборки отдельно не повторялись.
- Linux явно возобновлён владельцем, результаты в `docs/LINUX.md`. Прежнее указание о приостановке ниже — историческое.
- Sysmon, Windows channel ACL и audit policy в этом этапе не изменялись.

## Реализовано

- Windows Event Log API: EvtQuery, pull EvtSubscribe, EvtRender XML и durable bookmarks.
- System, Security, PowerShell Operational, Sysmon; отдельный явный wevtutil fallback.
- UID Windows-события учитывает EventRecordID; удалённый UID дополнительно разделён по агентам.
- ACK агента только после WAL, bounded outbox, retry и durable quarantine.
- HTTPS/rustls, проверка цепочки сертификата и SAN, private CA через REDTRACE_AGENT_CA.
- Non-loopback ingest без TLS не открывается; HTTP применяется только на loopback.
- UI управления агентами: выпуск, однократный показ/скрытие токена, last_seen, отзыв.
- Windows dev audit helper: UAC, PID/path-checked local IPC, restricted snapshots, выбранный apply/verify/rollback, verified Sysmon install и current-user read-only ACL grant.
- Sysmon preview: public artifact digest pin для official 15.22 плюс WinVerifyTrust. Elevated source-path read исключён: передаются frozen bytes. Существующий Sysmon не заменяется.
- Recovery последнего complete snapshot после потерянного ответа; отслеживание helper-процесса и межпроцессная блокировка.
- Native Windows npm commands, TypeScript, desktop build и NSIS packaging.

## Подтверждено на этом хосте

| Проверка | Результат |
|---|---|
| cargo fmt, clippy all-targets | Pass |
| Rust tests | 60 passed: 50 lib, 1 core, 7 ingest, 1 TLS, 1 Windows process TLS |
| npm lint, TypeScript | Pass |
| Web build / rendered HTML | Pass |
| Desktop release build | Pass |
| NSIS installed package / uninstall | Pass, isolated temporary installation with main/core/helper |
| Native real events → agent → core | Pass, ранее зафиксирован запуск с 154 событиями |
| Force-kill core → WAL recovery → agent retry | Pass |
| Separate core/agent processes over TLS | Pass, реальные native Windows events |
| Unknown CA / wrong SAN rejection | Pass |
| Desktop window / single-instance / sidecar cleanup | Pass |
| Real WebView UI agent register / show / hide / revoke | Pass |
| UAC apply/verify/rollback | Pass для logon, account-lockout, process-creation, powershell-script-block |
| Audit through actual WebView controls | Pass: selection, typed confirmation, UAC apply and rollback |
| Microsoft Sysmon 15.22 install | Pass: verified signature/public digest, UI confirmation/UAC, service+driver running; retained by owner |
| Normal-user live Sysmon ProcessCreate | Pass: native subscription, PID/PPID/command line |
| Current-user Security/Sysmon read grant | Pass: only read ACE, original descriptors preserved |
| ACL restore/re-grant/no-op | Pass: original restriction restored, read re-granted, no-op did not replace recovery reference |
| Recovery after failed native rollback attempt | Pass; исходная Logon policy восстановлена и проверена |

При первом UAC-тесте нативный AuditSetSystemPolicy не выполнил rollback. Путь исправлен на targeted auditpol /set по встроенным GUID; исходная policy восстановлена из защищённого snapshot. Затем полный цикл для всех четырёх настроек прошёл, включая registry values, и был подтверждён через реальные контролы Audit UI. Полного auditpol /restore в автоматическом rollback нет.

Финальный unsigned NSIS-пакет после Sysmon/ACL расширения: `src-tauri/target/release/bundle/nsis/REDTRACE_0.1.0_x64-setup.exe`, 3.24 MiB. Установлены и проверены main/core/helper; после проверки тестовая установка и её регистрация удалены. Sysmon и разрешённые read ACL остаются на хосте по указанию владельца.

В начале этапа Security был недоступен обычному пользователю, Sysmon отсутствовал. После явного разрешения владельца установлен официальный Sysmon 15.22 и выдан current-user read-доступ к двум каналам. Теперь обычный пользователь читает Security 4624 и Sysmon 1; normal-user core получает живые Sysmon process events. Sysmon остаётся установленным, read ACL остаются выданными. Audit policy/registry changes из прежних тестов восстановлены.

## Dev-запуск Audit

```powershell
$env:REDTRACE_AUDIT_DEV = '1'
.\src-tauri\target\release\redtrace-desktop.exe
```

В UI выберите действия, прочитайте privacy notice и введите APPLY REDTRACE AUDIT. Для rollback используйте ROLLBACK REDTRACE AUDIT. UAC возникает только при операции. Неподписанный helper разрешён исключительно для этого development этапа.

## Оставшиеся production gates

- Authenticode для helper/installer и политика доверенной доставки.
- Production signing/lifecycle Sysmon package, compatibility и recovery из incomplete installation; uninstall code fail-closed, реальное удаление не выполнялось, поскольку владелец указал оставить Sysmon.
- Reboot/sleep и проверка очищенного/rotated канала; normal-user Security/Sysmon validation уже выполнена.
- 24/72-hour soak, CPU/RSS/disk и burst/retention при нагрузке.
- Rate limits / lifecycle сертификатов и валидация на отдельной удалённой Windows-машине.
- npm development audit содержит 7 HIGH propagated entries от braces (нет доступного patched release) и 4 MODERATE в Drizzle/esbuild toolchain. npm audit --omit=dev: 0. Vulnerable Node tooling не включается в standalone Rust core/helper; static desktop UI использует отдельную Vite-сборку. Публичный web/dev service не считается production-ready.

## Оставленное состояние хоста

- Sysmon64 и SysmonDrv работают, version 15.22. Оставлены по явному выбору владельца.
- Public SHA-256 binary: 83D31F2478DC6716CFDBF69E5C384BF043072B5F0D8D7B2EEA365F709FDA4352.
- Current desktop user имеет отдельные read-only ACE на Security/Sysmon. Original ACLs находятся в защищённых snapshots и доступны для Restore через мастер.
- Normal-user Get-WinEvent подтверждён для Security 4624 и Sysmon 1.
- В native collector добавлены Sysmon 7/12/13 и DLL/registry/network context fields.
- Read ACL restore вернул исходное ограничение, затем read-доступ вновь выдан по разрешению владельца; no-op grant не заменил rollback reference.

Linux-этап приостановлен по указанию владельца; Windows-результаты не подтверждают Linux validation.
