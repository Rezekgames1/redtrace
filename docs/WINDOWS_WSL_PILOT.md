# Windows collector + Kali WSL agent

Подключение выполнено 08.10.2026: Windows desktop принимает реальные journald events от отдельного Linux агента в `kali-linux`.

## Текущий запуск

Обновление 12.10.2026: pilot использует административно установленный `C:\Program Files\REDTRACE\redtrace-desktop.exe` и embedded UI. `node scripts/wsl-pilot.mjs use-installed` выбирает этот executable для дальнейшего `start/status/stop`. Ниже сохранены исторические пути dev-запуска; не возвращать installed deployment к dev URL или делать core-only overwrite в Documents вместо installer upgrade. Аудит и поставка: `ADMIN_INSTALL_AND_AUDIT.md`.

- Исправление GUI после deployment: обычный `cargo build --release --manifest-path src-tauri/Cargo.toml` собрал оболочку с dev URL, а frontend 1420 не был поднят. В настоящем окне был `ERR_CONNECTION_REFUSED`, хотя core/agent работали. Поднят Vite frontend `127.0.0.1:1420`, окно обновлено через native UI Automation; подтверждены 100 Linux rows и 4657 matching events. Текущий UI mode — Vite dev/hot reload. `node scripts/wsl-pilot.mjs frontend` поднимает этот сервер; launcher сохраняет режим и запускает frontend при следующем desktop start.
- Production embedded UI собирать через Tauri CLI, либо явно с `--features tauri/custom-protocol`; наличие процесса/API не является проверкой GUI. Обычный Cargo release build без custom protocol недостаточен. Для текущей UI разработки повторная release-сборка не нужна.
- Windows приложение: `src-tauri/target/release/redtrace-desktop.exe`.
- API GUI: `127.0.0.1:9710`, session token создаёт desktop.
- HTTPS ingest: `172.22.80.1:9711`, только Windows WSL interface. TCP WSL→Windows проверен; firewall/system policies не менялись.
- Агент: `kali-wsl`, ID `375c2fda2e83e71b`, poll 2s, heartbeat 10s, initial lookback 15m.
- Windows база: `%LOCALAPPDATA%\REDTRACE`, существующие данные сохранены.
- Windows pilot config/TLS/logs: `%LOCALAPPDATA%\REDTRACE\wsl-pilot`, ACL новой папки только current user/SYSTEM.
- Linux executable/config/checkpoints/log: `~/.local/share/redtrace-wsl-pilot`, directory 700, credential file 600. Токен передаётся через environment, не CLI и не source.
- Windows `wsl.exe` keeper держит Linux процесс и WSL session; PID/start-time/executable проверяются перед остановкой.
- Финальное приложение запущено без WebView remote-debugging port.

В GUI выберите «Поля · DSL» и выполните:

```text
agent.name="kali-wsl"
```

## Управление из корня проекта на Windows

```powershell
node scripts/wsl-pilot.mjs status
node scripts/wsl-pilot.mjs start
node scripts/wsl-pilot.mjs stop
```

`start` использует уже зарегистрированного агента и действующие сертификаты. `stop` закрывает принадлежащее pilot окно и останавливает только проверенный Linux агент. Закрытие GUI завершает Windows core; это portable desktop-owned режим, не Windows Service/systemd deployment. Агент при недоступности core повторяет доставку; outbox пока RAM, source journal и checkpoint участвуют в recovery.

Первичная настройка и проверка: `node scripts/wsl-pilot.mjs setup` при закрытом pilot. `resume` продолжает начатую setup-сессию с её проверенным debug desktop. `setup` выпускает новый server leaf для текущего WSL gateway, использует прежний CA и token, если регистрация ещё действительна. CA pilot — 30 дней, server leaf — 14 дней. После смены WSL subnet нужны повторная setup/SAN/config проверка; повторный обычный `start` этого не делает скрытно.

## Что обнаружено и исправлено

- Journald допускает пустой/whitespace `MESSAGE`, ingest отклонял весь batch как `empty message`. Collector теперь сохраняет исходное значение в `event.original_message`, помечает `event.message_state=empty` и даёт явное описание записи без сообщения. Record cursor/UID сохраняются. Unit fixture проверяет совместимость с настоящим ingest normalizer.
- Pilot GUI checker принимал старые Windows rows сразу после submit фильтра. Исправлено ожидание результата Linux-фильтра; серверный `agent.id` поиск работал.
- GUI «Экспорт JSON» доступен из всех workspaces для последнего выполненного event query. «Скопировать JSON» показывает успех или ошибку clipboard. Conditional controls для отсутствующих данных, pending operations, mandatory columns и privileged helper сохраняют свои условия.

## Доказательства

`outputs/wsl-pilot/report.json` и `outputs/wsl-pilot/kali-on-windows.png`:

- 3894 Linux events в agent-filtered API на завершении GUI проверки, 100 Linux rows в настоящем Windows WebView.
- Diagnostic `logger` record дошёл через агент→HTTPS→WAL/index→SSE→GUI за 3960 ms в одном замере. Это реальная явно обозначенная journal-запись, не API demo injection; она остаётся в system journal.
- WAL/checkpoint errors — 0; durable agent checkpoint создан.
- Unknown CA, wrong SAN и invalid token отклонены; authenticated heartbeat — 200.
- После финального desktop restart TLS ingest и agent heartbeat снова работают; health/status подтверждены. `events_received` в registry — ACK-счётчик, может быть меньше общего уже сохранённого count после replay/ранних retries; не считать его точным lifetime уникальных events count.
- Windows 64 library tests и core all-targets clippy прошли; UI lint/typecheck, web build/9 Node tests, desktop UI build прошли. Windows release desktop и Linux release agent собраны. Эта итерация не заявляет повторный full-suite/long soak или production release.

Практический урок этой сессии: не повторять `setup`/PKI/native backfill ради каждой GUI проверки. Обычная эксплуатация — `start/status`; UI разработка — Vite/Tauri dev + hot reload; release rebuild один раз после проверок. Реальная база имеет десятки тысяч событий, WAL migration/segment index/compaction на startup иногда занимали более минуты. Этот performance backlog остаётся отдельным item M1/M7.
