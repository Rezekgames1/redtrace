# REDTRACE 0.2 — настройка и эксплуатация

Это инструкция для текущих исходников 0.2.0. Пакеты в `outputs/beta-20261013` относятся к предыдущему срезу: новые возможности появляются после пересборки. Системные политики и службы обычным запуском не изменяются.

## Коллектор и подключение устройства

В desktop-приложении откройте **Источники → Подключение устройств**. Укажите доступный агентам LAN IP или DNS и порт (по умолчанию 9711), затем включите приём. REDTRACE создаёт локальную CA и серверный сертификат, сохраняет настройки listener и поднимает HTTPS без OpenSSL. Интерфейс/API остаётся на loopback 9710. Доступность выбранного ingest-порта зависит от существующих правил firewall.

Введите имя устройства, выберите Basic или Extended и сохраните пакет подключения. Пакет действует 15 минут и содержит одноразовое разрешение и публичное доверие CA; постоянный токен выдаётся при подключении. На устройстве распакуйте полный комплект бинарников, включая `redtrace-service-agent`, и выполните:

```sh
redtrace-agent --enroll workstation-01.redtrace-enroll.json --install
```

На Windows в PowerShell используйте `./redtrace-agent.exe` из каталога комплекта. `--state-dir` задаёт отдельный абсолютный приватный каталог, если требуется. Существующая identity не перезаписывается новым enrollment. Без `--install` агент работает в текущем терминале. Пакет не переносит локальные module paths и фильтры коллектора на другой компьютер.

`--install` создаёт запуск при входе пользователя: Windows Scheduled Task, systemd user service на Linux, LaunchAgent на macOS. Права чтения системных журналов сохраняются такими, какие есть у пользователя. GUI сообщает ошибки доступа и backlog.

Чтобы коллектор продолжал сбор при закрытом окне, используйте **Настройки → Включить фоновый сбор**. После переключения GUI подключается к опубликованной локальной сессии. Для постоянного сбора до входа пользователя есть отдельная системная установка с явно выбранной учётной записью:

```sh
redtrace-admin install-service --binary /absolute/redtrace-service-agent --config /absolute/agent-state/service.json --agent --identity USER
```

Для коллектора используйте `redtrace`/`redtrace-service` из полного комплекта и конфигурацию коллектора, без `--agent`. Системная установка требует соответствующих административных прав; Linux использует systemd, macOS — LaunchDaemon, Windows — SCM. Для Windows поддерживается `--password-file` при использовании отдельной учётной записи. Обычный enrollment не выдаёт root/administrator, Full Disk Access или entitlement.

При работе без GUI:

```sh
redtrace-admin collector --data-dir /absolute/private-data --host siem.local --profile basic
redtrace --persistent --config /absolute/private-data/service.json
```

Команда `collector` работает при остановленном коллекторе и отказывает, если база занята. Повторная настройка сохраняет существующие параметры, если профиль явно не указан.

## Источники и нагрузка

Basic читает Windows Event Log, Linux journald или macOS Unified Log. Расширенные источники включаются явно в настройках; источники чужой ОС не запускаются. Include/exclude используют общий DSL поиска. Отфильтрованные события остаются внутренними маркерами курсора, без исходного содержимого и без выдачи в обычном поиске.

Linux audit reader читает уже существующий `audit.log` и агрегирует SYSCALL/EXECVE/CWD/PATH/PROCTITLE/EOE. Обрабатывает interleaved-группы, numeric rotation и незавершённые записи. Он не включает auditd, не устанавливает правила ОС и не забирает kernel audit socket у auditd. Для process coverage auditd должен уже записывать нужные события, а identity агента — иметь доступ к файлу.

macOS использует отдельный нативный Endpoint Security helper: exec/fork/exit, file create/rename/unlink/open/close, authentication/login/OpenSSH. Он требует root, Full Disk Access и одобренный Apple Endpoint Security entitlement. Сборка helper сама по себе права не предоставляет. Явный совместимый режим `REDTRACE_ES_BACKEND=eslogger` запускает штатный `/usr/bin/eslogger`; его JSON нормализуется тем же путём. Недоступность ES видна в health и не блокирует обычные журналы. Native ES ограничивает exec до 128 аргументов и размер записи/очереди; превышение не выдаёт молча усечённую команду, а отражается счётчиком dropped в health.

На Windows существующий native Event Log/Sysmon path сохраняется. Подготовка Windows Audit/Sysmon остаётся отдельным preview/apply/verify/rollback действием.

Конфигурация v1 содержит интервалы, лимиты batch/record/aggregation и spool. По умолчанию optional batch — до 512 событий и 4 MiB, отдельная запись — 128 KiB, агрегация — до 256 групп и 2 MiB, agent spool — до 20 000 событий и 32 MiB. Все optional inputs разделяют общий бюджет прохода; порядок источников чередуется. Фильтры компилируются при изменении конфигурации. Настройки агента сохраняются на сервере и применяются через heartbeat, без перезапуска.

Fleet показывает online/idle/stale/offline/degraded, last seen, delivery lag, pending count/bytes/oldest timestamp, retry/quarantine/refused counters и права/состояние модулей. Эти показатели диагностические: short samples не являются доказательством непрерывной сохранности за сутки.

## Правила и расследования

Экран **Правила** сохраняет пользовательские match/threshold/sequence/absence rules, DSL-исключения, numeric/CIDR conditions, grouping, suppression и metadata. При изменении правила увеличьте `revision`; optimistic `generation` защищает от устаревшего сохранения. История ограничена; live state ограничен по числу ключей и памяти. Sequence/absence используют массив `sequence`, threshold — `threshold` и `window_seconds`. Группы разделяются по identity хоста.

Replay запускается по сохранённой базе или отдельным fixtures, использует тот же движок и ограничивает события/алерты. Fixture-события не попадают в рабочую базу. Replay сортирует реальное RFC3339-время с учётом UTC offset, а равные времена сохраняют входной порядок. Live state и suppression восстанавливаются из checkpoint. Алерт можно связать с case; cases сохраняют статус, ссылки на alert/event UID и заметки.

## Сертификаты и токены

Серверный сертификат действует до 90 дней; при приближении срока он продлевается автоматически с hot reload. В настройках доступны ручное продление и двухэтапная смена CA. Сначала prepare добавляет новое доверие в heartbeat; activate разрешён после durable trust acknowledgement всех неревокированных агентов с действующим токеном. Устройства offline или ещё не подключившиеся требуют подключения либо явного отзыва identity перед переключением.

Токен агента автоматически обновляется через heartbeat перед expiry с ограниченным overlap старого токена. Изменённый приватный token-файл перечитывается без перезапуска. Ручная смена токена в GUI требует доставки нового файла агенту; отозванный токен отключает identity. TLS проверяет CA и SAN, redirects запрещены.

## Backup, перенос и возврат версии

В **Настройках** можно скачать потоковый checksummed backup работающего коллектора. Snapshot исключает session credentials/publication, temporary files и сами backups; содержит рабочую базу, конфигурацию, правила/cases, agent registry и PKI. Храните архив как приватные данные: это не зашифрованный публичный export.

Для CLI backup коллектор сначала останавливается:

```sh
redtrace-admin backup --data-dir /absolute/private-data --output /absolute/backup.rtbackup
redtrace-admin inspect --backup /absolute/backup.rtbackup
redtrace-admin restore --backup /absolute/backup.rtbackup --target /absolute/new-private-data
```

Restore проверяет checksums, безопасные пути и совместимость, создаёт новый каталог и не заменяет существующую базу. Пути, принадлежащие старому data directory, переносятся в новый; внешние module paths/filters сохраняются. До успешной проверки staging не активируется. Backup ограничен 4 GiB и 100 000 файлов.

Data/config/rules formats имеют version markers; legacy-v1 migration идемпотентна, будущая несовместимая версия отклоняется до записи marker. Для возврата приложения используйте бинарники совместимой версии и отдельную восстановленную базу; исходный каталог сохраняется. Автоматический updater и преобразование неизвестных будущих форматов в эту реализацию не входят.

## Подключаемый модуль NTA

NTA остаётся отдельным будущим процессом. Уже доступен protocol v1: append-only NDJSON `{ "protocol": 1, "module": "nta", "event": { ... } }`. В `sources.module_inputs` задаются уникальный ID, абсолютный путь и DSL query. Reader проверяет schema, назначает локальный UID/source/cursor и соблюдает общие budgets. Ошибка/oversized запись удерживает курсор перед ней; valid prefix сохраняется. При замене или усечении module-файла нужен явный reset cursor, чтобы не пропустить непрочитанные записи.

Basic не запускает NTA. Внешний producer управляет своими ресурсами отдельно; контракт позволяет подключить его без переделки хранилища и детектов.
