# REDTRACE — ранняя beta, сборка 2026-10-13

Этот документ описывает исходные бинарники `outputs/beta-20261013`. Текущие исходники 0.2.0 дополнены enrollment, настройками, rules, backup и расширенными источниками; для них используйте [настройку и эксплуатацию](SETUP_AND_OPERATIONS.md). Старые beta-пакеты автоматически не обновляются.

## Что устанавливать

Одна машина — **SIEM/collector** с базой и интерфейсом. Остальные устройства — **агенты**, отправляющие события collector по HTTPS. Elasticsearch, Java и Node.js конечному пользователю не нужны.

Артефакты этой beta собраны в `outputs/beta-20261013/`. Есть три GUI-поставки: Windows `.exe`, Linux x64 `.deb` и macOS arm64 `.dmg` с `REDTRACE.app`. Каждая содержит интерфейс и core; Node.js/Rust конечному пользователю не нужны. Архивы `.zip`/`.tar.gz` — отдельные CLI/agent packages, не GUI installers. macOS проверен на MacBook Air arm64 с macOS 26.6.2, Linux — на Kali WSL.

## 1. SIEM на Windows

1. Закройте прежнее окно REDTRACE. Дождитесь освобождения локального порта 9710. Не запускайте два collector на одной базе.
2. Запустите `REDTRACE-windows-beta-20261013-setup.exe`, подтвердите UAC. Установка — для компьютера, в `C:\Program Files\REDTRACE`.
3. Запустите REDTRACE из меню «Пуск». В portable GUI mode core запускается автоматически; закрытие GUI завершает сбор. Постоянный service mode описан ниже.
4. В «Источниках» проверьте доступность журналов и поступление событий. В «Аудите» доступны явные Windows apply/verify/rollback операции. Уже установленный Sysmon сохраняется; не переустанавливайте его ради обновления REDTRACE.
5. Данные находятся в `%LOCALAPPDATA%\REDTRACE`, если не задан `REDTRACE_DATA_DIR`. Перед обновлением/переносом сохраните копию каталога при остановленном core.

Windows GUI требует WebView2 Runtime. Бинарники beta пока без publisher signing; это контролируемая ранняя beta.

### 1.1. SIEM с GUI на Linux

Для Debian-подобной системы скачайте `REDTRACE-linux-x64-beta-20261013.deb` и из каталога с файлом выполните:

```sh
sudo apt install ./REDTRACE-linux-x64-beta-20261013.deb
redtrace-desktop
```

Либо запустите **REDTRACE** из меню приложений. Package manager подтянет `libwebkit2gtk-4.1-0` и `libgtk-3-0`; core уже входит в `.deb`. Запускайте GUI обычным пользователем, не через sudo. Для системного journal пользователю нужны соответствующие права (обычно группа `systemd-journal`). При отсутствии прав приложение показывает degraded, а не требует root для всего GUI.

Пакет проверен в Kali rolling/WSLg: настоящий GTK/WebKit GUI, 100 event rows, live delivery и завершение core при закрытии окна. Установка через apt на конкретных Ubuntu/Debian версиях ещё требует native проверки; сборка не объявляется универсальной для старых glibc/WebKit. `.rpm`/AppImage в этот набор не входят. Удаление приложения: `sudo apt remove redtrace`; пользовательскую базу удаляйте отдельно только если она больше не нужна.

### 1.2. SIEM с GUI на macOS / MacBook

1. Откройте `REDTRACE-macos-arm64-beta-20261013.dmg`.
2. Перетащите **REDTRACE.app** на **Applications / Программы** в окне образа.
3. Извлеките образ и запустите **Программы → REDTRACE**. Core стартует автоматически; Node.js, Homebrew и Rust не нужны.
4. Если macOS блокирует первый запуск неподписанной publisher beta, используйте **Настройки системы → Конфиденциальность и безопасность → Всё равно открыть**, затем подтвердите запуск выбранного приложения. SIP и глобальные Gatekeeper-настройки не меняйте.

Это Apple Silicon **arm64**, не Intel Mac. App имеет локальную ad-hoc signature для целостности bundle, но не Developer ID/notarization. Проверен настоящий onscreen GUI на macOS 26.6.2: 70 native Unified Log events, frontend health/search/live requests, date/time API и закрытие GUI/core. Для обычного источника Unified Log отдельный auditd устанавливать не требуется. Endpoint Security coverage пока не входит в beta.

Пользовательская база macOS находится в `~/Library/Application Support/REDTRACE`, если не переопределён `REDTRACE_DATA_DIR`. Для удаления перенесите `.app` в Корзину; база удаляется отдельно. После установки можно включить remote ingest через environment или persistent config, как ниже; локальный GUI/core mode и отдельный foreground collector одновременно на 9710 не запускайте.

## 2. Приём событий с других устройств

Выберите постоянный LAN IP/DNS collector. Пример ниже: `192.168.31.96:9711`.

### TLS

Нужны `server.pem`, `server.key` и сертификат доверенного CA `ca.pem`. Server certificate должен иметь **IP SAN `192.168.31.96`** или DNS SAN используемого имени. TLS-ключ остаётся на collector, на агенты копируется только CA. Сертификат из короткого сетевого теста истекает через сутки и для постоянной установки не подходит.

На Linux/macOS PKI можно создать OpenSSL. Выполняйте команды в отдельном приватном каталоге; реальные ключи не кладите в исходники:

```sh
umask 077
mkdir -p "$HOME/.config/redtrace-tls"
cd "$HOME/.config/redtrace-tls"
openssl req -x509 -newkey rsa:3072 -nodes -keyout ca.key -out ca.pem -days 365 -subj '/CN=REDTRACE Pilot CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -newkey rsa:3072 -nodes -keyout server.key -out server.csr -subj '/CN=192.168.31.96'
printf '%s\n' 'subjectAltName=IP:192.168.31.96' 'basicConstraints=critical,CA:FALSE' 'extendedKeyUsage=serverAuth' 'keyUsage=critical,digitalSignature,keyEncipherment' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 90 -sha256 -extfile server.ext
```

Замените адрес в CN и SAN своим. CA private key нужен для выпуска сертификатов, не для работы collector; храните его отдельно. На Windows можно подготовить PKI через WSL/OpenSSL и перенести server certificate/key в защищённый пользовательский каталог.

### Включение listener в Windows GUI mode

Закройте REDTRACE и запустите из PowerShell:

```powershell
$env:REDTRACE_INGEST_BIND = '192.168.31.96:9711'
$env:REDTRACE_INGEST_CERT = 'C:\Users\Alice\AppData\Local\REDTRACE-TLS\server.pem'
$env:REDTRACE_INGEST_KEY = 'C:\Users\Alice\AppData\Local\REDTRACE-TLS\server.key'
& 'C:\Program Files\REDTRACE\redtrace-desktop.exe'
```

Пути замените своими. GUI/API остаётся локальным на `127.0.0.1:9710`; наружу открывается только ingest. Non-loopback ingest без TLS не запускается.

Если firewall блокирует подключение, в административном PowerShell добавьте точечное правило под свои адреса:

```powershell
New-NetFirewallRule -Name REDTRACE-Ingest-LAN -DisplayName REDTRACE-Ingest-LAN -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9711 -LocalAddress 192.168.31.96 -RemoteAddress 192.168.31.216 -Profile Private -Program 'C:\Program Files\REDTRACE\redtrace.exe'
```

Для нескольких агентов задайте разрешённые IP/подсеть вашей LAN. Откат: `Remove-NetFirewallRule -Name REDTRACE-Ingest-LAN`.

### Регистрация агента

В GUI **«Источники» → зарегистрировать агента** задайте имя устройства. Скопируйте выданный токен в приватный `agent.token` на endpoint. Токен показывается однократно. Каждому устройству выдаётся свой токен; имя не заменяет identity. Старый токен после revoke не принимается. API management требует local session token даже в dev unauthenticated mode.

## 3. Агент Windows

Распакуйте Windows agent package в каталог только для нужного пользователя. Создайте файл `agent.token`, вставьте выданный токен одной строкой. Скопируйте `ca.pem` с collector.

```powershell
$env:REDTRACE_AGENT_CA = "$HOME\redtrace-agent\ca.pem"
& "$HOME\redtrace-agent\redtrace-agent.exe" --server https://192.168.31.96:9711 --token-file "$HOME\redtrace-agent\agent.token" --name windows-laptop --state-dir "$env:LOCALAPPDATA\redtrace-agent"
```

Для чтения Security/Sysmon нужны соответствующие права/ACL и включённый аудит. Агент сам эти права не выдаёт. Возможен запуск без повышения привилегий при уже настроенных правах.

## 4. Агент Linux

Распакуйте Linux package. В приведённом примере файлы лежат в `$HOME/redtrace-agent`:

```sh
mkdir -p "$HOME/redtrace-agent" "$HOME/.config/redtrace-agent"
chmod 700 "$HOME/.config/redtrace-agent"
chmod +x "$HOME/redtrace-agent/redtrace-agent"
chmod 600 "$HOME/.config/redtrace-agent/agent.token"
REDTRACE_AGENT_CA="$HOME/.config/redtrace-agent/ca.pem" "$HOME/redtrace-agent/redtrace-agent" --server https://192.168.31.96:9711 --token-file "$HOME/.config/redtrace-agent/agent.token" --name linux-host --state-dir "$HOME/.local/share/redtrace-agent"
```

Создайте token file и скопируйте CA перед запуском. Пользователь должен читать journald, обычно через группу `systemd-journal`; после изменения групп нужна новая login session.

**Linux audit:** используем `auditd + journald`. Debian/Ubuntu: `sudo apt install auditd audispd-plugins`; Fedora/RHEL: `sudo dnf install audit`. Включение службы: `sudo systemctl enable --now auditd`. Политику audit rules выбирайте под хост, не включайте аудит каждого syscall без оценки объёма. В этой beta collector читает **journald**, а прямой `/var/log/audit/audit.log` reader и агрегация `SYSCALL/EXECVE/CWD/PATH` ещё не реализованы. Установка auditd сама по себе не означает, что весь audit trail уже виден в REDTRACE.

## 5. Агент MacBook/macOS

Распакуйте arm64 package. Node.js и Homebrew агенту не нужны:

```sh
mkdir -p "$HOME/.config/redtrace-agent"
chmod 700 "$HOME/.config/redtrace-agent"
chmod +x "$HOME/redtrace-agent/redtrace-agent"
chmod 600 "$HOME/.config/redtrace-agent/agent.token"
REDTRACE_AGENT_CA="$HOME/.config/redtrace-agent/ca.pem" "$HOME/redtrace-agent/redtrace-agent" --server https://192.168.31.96:9711 --token-file "$HOME/.config/redtrace-agent/agent.token" --name macbook --state-dir "$HOME/.local/share/redtrace-agent"
```

Источник этой beta — Unified Log: `sshd`, `sshd-session`, `sudo`, выбранные `authd` события. Исправлены native timestamps, стабильная identity по boot/mach time и bounded NDJSON reader. Исторический процесс не обогащается command line случайного нового процесса с тем же PID.

**macOS audit:** BSM/auditd deprecated, по умолчанию отключён начиная с macOS 14; проверено по `man audit` непосредственно на macOS 26.6.2. Основной дальнейший источник — **Endpoint Security**, для пилота можно исследовать штатный `eslogger`; ему нужны root и подходящий Full Disk Access. Интеграция ES в REDTRACE ещё не реализована. SIP отключать не требуется. Unified Log не даёт полного process/file/network покрытия Sysmon.

## 6. Collector без GUI, Linux/macOS

CLI package содержит `redtrace` и `redtrace-service-agent`. Можно запустить общий collector напрямую. Автоматический приватный local session создаётся в persistent mode:

```sh
chmod +x redtrace redtrace-agent redtrace-service redtrace-service-agent
REDTRACE_SERVICE_MODE=persistent REDTRACE_DATA_DIR="$HOME/.local/share/redtrace-collector" REDTRACE_INGEST_BIND=192.168.31.96:9711 REDTRACE_INGEST_CERT="$HOME/.config/redtrace-tls/server.pem" REDTRACE_INGEST_KEY="$HOME/.config/redtrace-tls/server.key" ./redtrace
```

Укажите **адрес самой collector-машины**, не чужой Windows IP. Эта команда запускает CLI core; для обычного интерфейса используйте соответствующий GUI installer из раздела 1. Standalone API доступен локально и требует capability из private session; не открывайте порт 9710 на внешние интерфейсы.

Windows SCM и Linux systemd команды/config/templates: [SERVICE_MODE.md](SERVICE_MODE.md). Установка служб не выполняется автоматически beta installer. macOS foreground и authenticated attachment проверены; готовый launchd installer/boot profile ещё отсутствует.

## 7. Проверка поступления и фильтры

В GUI «Источники» проверьте heartbeat и число событий, затем откройте «События»:

```text
agent.name="macbook"
agent.id="ID_ИЗ_РЕГИСТРАЦИИ"
source="macos.sshd-session"
```

Выберите DSL для запросов по полям. Для обычного текста используйте contains. Фильтр **«Период»**: всё время, 15 минут, час, 24 часа, 7 дней или **«Дата и время…»**. Задайте локальные дату/время «С»/«До» и нажмите **«Выполнить»**. Начало включительно, окончание не включается. Для целого дня выбирайте 00:00 нужного дня → 00:00 следующего. Даты переводятся в UTC; поиск, пагинация, график и JSON export используют тот же применённый фильтр. Сырые timestamps событий остаются UTC.

По умолчанию агент опрашивает журнал раз в 5 секунд. Spool сохраняет pending на диск и восстанавливает их после kill/reboot; cap по умолчанию 20 000 событий / 32 MiB. Неподтверждённые события не удаляются по сетевому timeout. После token rotation замените private token file и перезапустите агент; hot reload токена пока нет. Не удаляйте spool при перезапуске.

Durable receipt cache collector отделён от текущего retention: до 65 536 UID, 24 часа, журнал до 4 MiB. За пределами этого окна удалённые retention события могут снова появиться при очень старом replay; бесконечное хранение дедупликации не обещается.

## 8. Проверенный сетевой результат и ресурсы

Прямой LAN HTTPS Mac `192.168.31.216` → Windows `192.168.31.96`: 144 реальных события; 103 наблюдённых UID сохранились при restart collector; 35 событий durable offline spool пережили force-kill агента; после восстановления pending=0. Неверный токен и недоверенный CA отклонены. Fresh SSH delivery: 7.377 s в одном наблюдении при default poll 5 s — это не p95/SLA. Изолированная база; рабочая база не менялась. Тестовое firewall-правило удалено.

Замер старой работающей Windows-сборки, 10 секунд: core working set **408.62 MiB**, private commit **882.75 MiB**; GUI и дочерние процессы вместе с core working set **717.87 MiB**, private commit **1193.99 MiB**. CPU всех процессов ≈**0.147% машины** на 18 logical CPU, core ≈1.716% одного ядра. Новый Mac agent в коротком тесте RSS ≈**14 MiB**, CPU 2.2–13.5% одного ядра во время коротких backfill/startup наблюдений. Это разные метрики и нагрузки, не стабильный ресурсный SLA и не замер новой Windows beta на той же базе.

Для пилота разумно выделить collector-хосту минимум 4 GiB RAM и отдельное место под базу. Default retained segments cap 512 MiB / 7 дней не включает WAL, alerts, quarantine и временное место compaction. При больших объёмах отдельно измеряйте рост базы, RSS и delivery lag.
