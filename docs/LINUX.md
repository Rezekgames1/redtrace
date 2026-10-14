# Linux SIEM — journald

## Последующее обновление GUI/live

Актуальный отчёт: `docs/GUI_AUDIT.md`. Linux Rust tests — 60 passed. Authenticated SSE→настоящий GTK/WebKit UI проверен без ручного обновления: финальный smoke 1339 indexed events, 100 UI rows, diagnostic live record появился за 938 ms; single instance и закрытие sidecar прошли. Финальный пакет в `outputs/linux/REDTRACE_0.1.0_amd64.deb` пересобран (5.30 MiB). Ниже сохранены исходные результаты предыдущей итерации.

Этап возобновлён владельцем 08.10.2026. Linux использует общий Rust core, WAL, сегменты, поиск, детекты и remote-agent протокол. Коллектор читает доступный system journal через `journalctl`, включая службы, SSH, sudo, kernel и audit-записи, попавшие в journald.

## Запуск

Нужны Linux с systemd/journald и `journalctl` в PATH. Для standalone web UI:

```bash
cargo build --release --bins --locked
REDTRACE_ALLOW_UNAUTHENTICATED=1 REDTRACE_LOOKBACK=15m ./target/release/redtrace
```

Во втором терминале: `npm ci && npm run dev`, затем `http://localhost:3000`. API остаётся на loopback `127.0.0.1:9710`. Открытый локальный режим включён явно для web development; desktop автоматически использует случайный API token. Для standalone с авторизацией задайте `REDTRACE_API_TOKEN` длиной не менее 32 байт и передавайте `x-redtrace-token` в API-запросах.

Desktop Linux использует существующую Tauri-оболочку:

```bash
npm ci
npm run desktop:build -- --bundles deb --ci --no-sign
```

На Debian/Ubuntu для сборки нужны Rust/Node и `libwebkit2gtk-4.1-dev`, `libayatana-appindicator3-dev` (либо дистрибутивный `libappindicator3-dev`), `librsvg2-dev`, `patchelf`, C/C++ toolchain. В текущей Kali WSL зависимости GTK/WebKit и native Node/npm установлены с явного разрешения владельца. apt подтянул обновления зависимостей rolling-дистрибутива; после установки systemd сообщает `running`, journal читается.

Для изолированной сборки из Windows checkout, без смешивания Windows/Linux `node_modules`:

```bash
python3 scripts/build-linux.py --workspace /path/to/existing-parent/redtrace-linux-build
```

Скрипт копирует исходники в отдельное дерево, делает native `npm ci`, использует отдельный `CARGO_TARGET_DIR` и сохраняет `.deb` в `outputs/linux/`. `prepare-sidecar.mjs` учитывает `CARGO_TARGET_DIR`. Собранный пакет: `outputs/linux/REDTRACE_0.1.0_amd64.deb`, 5.30 MiB. Он содержит desktop shell и core; агент собирается отдельным Rust binary. Пакет собран на Kali rolling: переносимость на старые Ubuntu/Debian требует сборки на соответствующей минимальной версии, текущая сборка не заявляется универсальной.

## Данные и разрешения

- Сбор read-only, без автоматического включения auditd или изменения прав журналов.
- `journalctl --since -15m --output=json --no-pager` показывает доступные тому же пользователю данные. Для полного system journal может требоваться группа `systemd-journal` или дистрибутивная `adm`; после ручного изменения групп нужен новый login.
- Сообщения journalctl о неполном доступе видны в `degraded`/`last_error`; отсутствие journalctl или сбой процесса — `error` с backoff/retry.
- Нормализуются hostname, boot ID, unit, UID/GID, executable, command line, PID, audit session/login UID и syslog priority. SSH дополняет IP/port/user; sudo — user, target user, TTY, PWD, COMMAND. Audit-записи дополняют PID/PPID, executable, syscall, outcome.
- PPID берётся из audit при наличии; для свежих событий возможен best-effort `/proc/PID/status`. Исторический PID не связывается с текущим процессом. Командная строка/PPID не всегда присутствуют: общий сбор всех exec/process-create требует отдельно настроенного audit/eBPF источника.
- Отдельный `/var/log/audit/audit.log`, обычные syslog-файлы и контейнерные файлы не читаются этим коллектором. Многострочные audit-события не собираются в единый exec-event; enrichment предназначен для отдельных journal records.
- Историческая выборка ограничена первыми 4096 событиями или 8 MiB JSON за проход, запись — 1 MiB. Продолжение идёт через durable cursor; локальный follow дочитывает хвост, агент повторяет проход после ACK. UID учитывает journal cursor, в том числе при remote-доставке.
- При недействительном cursor используется timestamp checkpoint с перекрытием и дедупликацией. Вакуумированные/удалённые записи восстановить нельзя.
- `REDTRACE_DATA_DIR` задаёт каталог базы. `REDTRACE_LOOKBACK` принимает положительное число до 10080 с суффиксом `m`, `h`, `d`.

## Remote agent

Дальнейшие работы по удалённым hosts, systemd lifecycle и durable/streaming delivery: `docs/IMPLEMENTATION_PLAN.md` (M2–M6). Описанный ниже запуск использует текущий agent, а не уже реализованный service installer.

На ядре включите TLS ingest и зарегистрируйте агента через «Источники». На Linux endpoint задайте `REDTRACE_AGENT_TOKEN`, при частном CA — `REDTRACE_AGENT_CA`, затем:

```bash
./target/release/redtrace-agent --server https://siem.example:9711 --name linux-host --poll 5
```

Для постоянного запуска используйте systemd-службу с непривилегированным пользователем, которому вручную разрешено читать нужный journal, защищённым EnvironmentFile для токена и writable-каталогом `REDTRACE_AGENT_STATE`. Сертификат должен иметь SAN имени сервера. Протокол сохраняет retry/ACK после WAL, quarantine, изоляцию курсоров и отзыв токенов.

## Проверка 08.10.2026

```bash
cargo test --all-targets --locked
cargo clippy --all-targets -- -D warnings
python3 scripts/smoke-linux.py
```

Smoke работает с временной базой и регистрацией агента. Он добавляет одну явно обозначенную diagnostic-запись через `logger`, чтобы проверить live follow; она остаётся в system journal. Демо-события в рабочий UI не подставляются. Все процессы завершаются, временная база удаляется. Порты 9710/9711 должны быть свободны.

Подтверждено на Kali WSL2, systemd, kernel 6.6.87.2: первый smoke — 112 реальных backfill events, 113 событий от Linux-агента, 226 local+remote событий после restart; повторный после ограничения backfill — 177/178/356, после явного `--no-tail` — 114/115/230. Authenticated API, contains/exact/exclusion, live follow, crash recovery/dedup, revoke прошли. Linux Rust tests: 59 passed; Windows core/desktop clippy проходит. Следующий раздел описывает отдельно подтверждённый Linux desktop.

Desktop validation после установки зависимостей:

```bash
python3 scripts/smoke-desktop-linux.py --package outputs/linux/REDTRACE_0.1.0_amd64.deb --output outputs/linux
```

Пакет извлечён во временный каталог без установки в `/usr`. Настоящий GTK/WebKit WebView в WSLg/X11 показал 100 реальных Linux event rows (подтверждено accessibility tree); authenticated API — 3342 indexed events в первом запуске, 3181 в повторном с resource snapshot. PID/path-checked дочерний core, 401 без токена, single instance и graceful window close с завершением sidecar прошли. Отчёт: `outputs/linux/report.json`, лог: `outputs/linux/desktop.log`. GUI smoke требует Python GI/Atspi и X11 (`xwininfo`); токены и содержимое событий в отчёт не записываются.

Однократный `ps rss` snapshot повторного GUI smoke: core 27812 KiB (~27 MiB), desktop/GTK 211136 KiB (~206 MiB), WebKit web process 438692 KiB (~428 MiB), WebKit network process 70528 KiB (~69 MiB), journalctl 13184 KiB (~13 MiB). RSS shared pages могут учитываться несколько раз, это не unique/private memory и не soak benchmark. Rust core лёгкий, общий WebView process tree требует отдельного performance-профилирования.

Оставшиеся проверки: установка через системный package manager, отдельный Linux host, совместимость с минимальной версией дистрибутива, reboot, journal vacuum, длительный soak. Linux clippy component отсутствует в текущем rustup toolchain.
