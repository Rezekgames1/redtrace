# Сбор событий с Windows-машин

## На машине-коллекторе

Подготовьте PEM certificate/key для TLS. DNS/IP, по которому подключаются агенты, должен присутствовать в SAN сертификата. Приватный ключ храните вне исходников.

Из корня проекта:

```powershell
$env:REDTRACE_INGEST_BIND = '0.0.0.0:9711'
$env:REDTRACE_INGEST_CERT = 'C:\REDTRACE\certs\collector.pem'
$env:REDTRACE_INGEST_KEY = 'C:\REDTRACE\certs\collector-key.pem'
.\src-tauri\target\release\redtrace-desktop.exe
```

Для установленной версии задайте те же переменные перед запуском её desktop executable. UI/API останутся на loopback; наружу выходит только TLS ingestion.

В «Источниках» введите имя машины и выпустите токен. Он показывается один раз. Сохраните его в выбранном secret store и передайте endpoint через окружение процесса. В реестре коллектора остаётся SHA-256-хэш.

Разрешите TCP 9711 на машине-коллекторе только для адресов управляемых endpoints. Приложение не создаёт firewall rules автоматически.

## На Windows endpoint

Скопируйте `target\x86_64-pc-windows-msvc\release\redtrace-agent.exe`. Node.js, Rust toolchain, Tauri и WebView2 агенту не нужны.

```powershell
$env:REDTRACE_AGENT_SERVER = 'https://collector.example:9711'
$env:REDTRACE_AGENT_TOKEN = '<выданный-токен>'
$env:REDTRACE_AGENT_NAME = $env:COMPUTERNAME
$env:REDTRACE_AGENT_CA = 'C:\REDTRACE\certs\organization-ca.pem'
.\redtrace-agent.exe
```

REDTRACE_AGENT_CA требуется для частного CA; для цепочки от доверенного публичного CA его можно не задавать. HTTPS проверяет цепочку и SAN. Для remote HTTP агент откажет в запуске.

Агент читает System, Security, PowerShell Operational и уже установленный Sysmon. Нужны соответствующие права чтения и включённые audit policies на самом endpoint. Domain lockout 4740 собирайте с DC; включение User Account Management на рабочей станции не переносит DC-события на неё.

Управление audit policy/Sysmon на endpoint выполняется в отдельном Windows desktop-мастере. Агент сам не меняет политики и не устанавливает драйверы. Для обычного пользовательского сенсора мастер может выдать только read-доступ к Security/Sysmon с сохранением исходного ACL.

## Доставка и диагностика

- Checkpoints по умолчанию: `%LOCALAPPDATA%\redtrace-agent\checkpoints.json`.
- Checkpoint продвигается после durable ACK коллектора.
- Потерянный ответ приводит к повтору; server dedup учитывает agent ID и EventRecordID.
- Buffer: 20 000 событий / 32 МБ. Пока есть pending batch, агент не повторяет backfill.
- Отклонённый batch разделяется; одиночное событие сохраняется в `quarantine` с fsync. Quarantine ограничен 16 МБ.
- При полном quarantine pending event сохраняется для повторной обработки.
- 401 завершает агент; выпустите новый токен и перезапустите процесс.
- GUI показывает last_seen, количество событий и отзыв токена; `/api/health` содержит remote_ingest и duplicate counters.
- Поиск конкретного endpoint: `agent.name:"HOST"` или `agent.id:<id>`.

Windows native collector — default. Для явного старого polling задайте `REDTRACE_WINDOWS_COLLECTOR=wevtutil`.

Текущая проверка покрывает отдельные core/agent процессы на одном Windows-хосте по TLS. Развёртывание на другой машине и её права/политики проверяются при подключении этой машины.

## Следующие этапы

Текущий агент работает периодическими проходами (default poll 5s), outbox хранится в RAM. Эти возможности не заменяют Windows Service и durable offline spool. Реальный сетевой пилот, service lifecycle, streaming delivery, GUI onboarding и certificate/token rotation запланированы в `docs/IMPLEMENTATION_PLAN.md` (M2–M6). Production budgets/signing/reliability gates описаны там же; готовность проверяется отдельно для каждого этапа.
