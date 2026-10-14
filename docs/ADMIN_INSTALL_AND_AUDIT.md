# Административная установка и аудит — 12.10.2026

## Реальное развёртывание

- NSIS использует `perMachine`: UAC, `C:\Program Files\REDTRACE`, HKLM uninstall registration.
- Установлены desktop/core/audit-helper/uninstaller. Directory и binaries принадлежат Administrators, System/Administrators имеют Full Control, Users — Read/Execute. Installer hooks устанавливают эти права; произвольный install path отклоняется.
- Installed desktop включает audit executor без `REDTRACE_AUDIT_DEV`. Перед запуском helper проверяются расположение Program Files, owner/DACL, отсутствие reparse points и встроенный SHA-256 pin. Read handles удерживаются во время операции. Helper проверяет protected desktop peer и PID/path named-pipe server.
- Подпись publisher для REDTRACE ещё отсутствует. Защищённая admin installation и digest pin не являются Authenticode/public production release; сертификат подписи не создавался.
- GUI работает с embedded frontend, без зависимости от Vite 1420. Pilot launcher переведён на установленное приложение; TLS CA/token и существующая база остаются в прежних защищённых data directories.
- Финальный запуск: installed desktop PID 20140, owned core PID 25076, Kali agent PID 280; PID могут меняться. TLS ingest и read-only Security/Sysmon access подтверждены после upgrade. Working directory — прежний `%LOCALAPPDATA%\REDTRACE`; data/evidence/quarantine не очищались.

## Аудит

Проверен настоящий установленный GUI с ordinary desktop + elevated helper. Перед apply/rollback фиксировались native AuditQuerySystemPolicy flags и registry values. Все четыре действия применились, verify прошёл, после rollback состояние совпало с baseline. Затем профиль применён повторно и оставлен включённым по запросу владельца.

| Настройка | До проверки | После применения | После rollback | Итог |
|---|---|---|---|---|
| Logon success/failure | flags 3 | 3 | 3 | 3 |
| User Account Management / 4740 | flags 1 | 1 | 1 | 1 |
| Process Creation / 4688 | flags 0 | 1 | 0 | 1 |
| Command line DWORD | 1 | 1 | 1 | 1 |
| Script Block Logging DWORD | absent | 1 | absent | 1 |

Созданы явно обозначенные benign process/script markers. 4688 с command line и 4104 ScriptBlockText поступили в SIEM. Политика 4740 проверена по effective state; пользовательские учётные записи для генерации lockout не блокировались.

В процессе проверки обнаружен дефект native pull subscription: reset signal после empty EvtNext мог потерять wake-up. Исправлено reset-before-drain, bounded drain 256 и проверка очереди также после timeout. После исправления 4688/4104 live checks проходят. Финальный NSIS содержит исправленный core; SHA-256 установленного core совпадает с build artifact.

## Кнопки и snapshots

- Четыре selectable audit actions, apply и rollback работают через UAC с explicit confirmation.
- «Проверить состояние Windows» — реальный read-only elevated запрос, отображает effective flags/registry и обнаруживает protected snapshots независимо от localStorage origin.
- Вместо постоянно disabled Sysmon checkbox — кнопка перехода к отдельной настройке Sysmon.
- Sysmon preview сохраняет signature/hash checks и frozen payload. Существующая установка показывается явно и не заменяется. Реальный uninstall/install-existing cycle не выполнялся: Sysmon64/SysmonDrv сохранены Running по указанию владельца.
- Read-only grant проверен; existing user read permissions сохранены. Restore ACL использует local reference либо обнаруженный protected snapshot. Original user ACL в этой итерации не удалялся ради теста.
- Restore/remove/apply кнопки имеют штатные условия: snapshot, preview, confirmation, busy, installed-state. Они не включаются без необходимых данных.

Итоговый protected audit snapshot для возврата: `4f740ebe26568ca844e588f5aed5b691`. Existing read-access reference: `4715f985f68e7fdcc4a434d0636b7429`; Sysmon install reference: `0d5b58ef7e79d55283e9d13efe1ecf93`. Reports не содержат credentials.

## Evidence / проверки

- `outputs/windows-admin/audit-report.json`: baseline/applied/rollback/final values, event checks и read grant — PASS.
- `outputs/admin-preview.png`: installed normal-user GUI «ГОТОВ К ПРИМЕНЕНИЮ».
- **85 Windows Rust tests**, core/desktop clippy, fmt, TypeScript и targeted ESLint — PASS. Current UI checks используются вместе с ранее прошедшим 16-test набором.
- Precommit recheck: 82 Rust tests и 16 UI tests — PASS. Три process tests требуют свободный API port 9710; query API и Windows TLS recheck завершились на проверке занятого порта рабочего SIEM, после чего эти три tests исключены из повторного запуска. Предыдущие process PASS остаются evidence; рабочая установка не останавливалась ради recheck.
- Admin install и upgrade — exit 0; HKLM registration и actual owner/DACL проверены.
- Elevated test harness не получил WebView debug target; functional checks выполнены в штатном normal-user GUI с UAC helper. Это не скрытое доказательство elevated GUI compatibility.
- Первый event assertion не прошёл; его audit snapshot был восстановлен и verified. Финальный runner имеет failure rollback с явным snapshot ID перед очисткой временной базы.
- Отдельное наблюдение после запуска рабочей базы: Sources отображал сохранённую ошибку Sysmon subscription `EvtNext: os error 4317` / degraded. Пройденные 4688/4104 checks не закрывают все reconnect/rollover cases; error clearing и устойчивость всех native channels остаются отдельной проверкой. Не трактовать audit PASS как отсутствие любых collector warnings.

Поставка: `src-tauri/target/release/bundle/nsis/REDTRACE_0.1.0_x64-setup.exe`, около 3.30 MiB, unsigned. Установленный core SHA-256: `138E6557937E683B76058EF2740B88BB17706C68353B70D449034EFFB27E7F0B`. Helper pin: `4F42493180365C5DACF2F2C7574DA6160371C818439140D8E1AF291D82CA4AEF`.

Настройки относятся к Windows-хосту с SIEM. Remote agent management пока не меняет auditd/Windows policies на удалённых endpoints. Service lifecycle, signing и остальные resource/reliability gates остаются в implementation plan.
