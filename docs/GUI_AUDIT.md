# GUI audit и live-события — 08.10.2026

Следующее обновление: сохранённые представления/колонки и короткая нагрузка — `docs/VIEWS_AND_LOAD.md`. Длинный soak не подтверждён, его повтор отменён владельцем.

## Область проверки

Проверены реальные Windows WebView экраны событий, алертов, источников, Windows Audit preview и диагностики. Экран событий проверен при ширине 1440 и 1024: 100 реальных строк, без горизонтального overflow. Linux проверен в настоящем GTK/WebKit WSLg UI из извлечённого `.deb`.

Скриншоты: `outputs/gui-before.png`, `outputs/gui-after.png`, `outputs/gui-after-1024.png`, `outputs/gui-sources.png`, `outputs/gui-alerts.png`, `outputs/gui-audit.png`, `outputs/gui-diagnostics.png`. Рядом с текущими PNG — `.png.json` с viewport/overflow/числом строк. Изображения содержат локальные пути/имена из реальных журналов и не предназначены для публичной публикации.

## Выявлено и исправлено

| Приоритет | Наблюдение | Изменение |
|---|---|---|
| Высокий | Опрос GUI раз в 2,5 секунды; ручной refresh выглядит необходимым | Authenticated SSE `/api/live`, reconnect/resync; «Обновить логи» убрана из ленты |
| Высокий | Автообновление сбивает просмотр истории | Пауза при прокрутке/пагинации, явный возврат в эфир; сбор продолжается |
| Высокий | Выбранное событие исчезает из окна последних 100 строк | Детали удерживают immutable event независимо от новых строк |
| Высокий | Исторический backlog при старте выглядит как готовый live-сбор | Отдельная фаза `backfilling`; Windows native stream обозначает `streaming`; GUI показывает загрузку истории |
| Средний | Постоянные боковые панели и график оставляют узкий центр | Поля, детали и график закрыты по умолчанию; адаптивные панели |
| Средний | Дублируются навигация/экспорт; есть неработающие элементы | Убраны placeholder «Аналитика»/«Сохранить представление», fake time selector и дублирующий JSON-export |
| Средний | В сводке bookmarks и служебные поля | Короткий allowlist аналитических полей; полный набор — «Все поля»/JSON |
| Средний | `н/д`, повторные file paths и JSON используются как контекст строки | Только полезный отличающийся контекст; JSON строится лениво |
| Средний | Технические метрики/синтаксис занимают основной экран | Метрики в «Источники»/«Диагностика», синтаксис в disclosure |
| Средний | Пустые алерты показывают четыре крупные карточки и два refresh | Сводка раскрывается по запросу; автоматическое обновление и простое пустое состояние |
| Средний | Команды аудита постоянно раскрыты, диагностика выглядит как live-метрики | Команды в disclosure; privacy/подтверждение сохранены; диагностика подписана как timestamped snapshot |
| Средний | На Linux отображается неприменимый Windows Audit plan | Объяснение read-only сбора вместо Windows action cards |
| Низкий | Ctrl K объявлен, но не работает | Ctrl/Cmd K фокусирует поиск; Esc закрывает панели/конструктор |
| Низкий | График сдвигает часы, рисует ненулевые нули и неверную ось | UTC-hour buckets, реальные нули и количества |

## Live и ограничение нагрузки

`src/main.rs:297` — SSE под тем же token middleware, что остальные API. `src/main.rs:591` — уведомление после WAL/index updates и обработки rotation. `src/live.rs` использует `watch` revision без неограниченной per-client очереди. SSE содержит только число, не пользовательские события.

`app/events/api.ts:168` использует streaming fetch с `x-redtrace-token`; токен не попадает в URL. Heartbeat — 10 секунд. Reconnect backoff — 0,5–10 секунд, первое сообщение после подключения инициирует resync.

`app/page.tsx:128` объединяет уведомления в последовательные синхронизации. Устаревший ответ не перезаписывает новый ручной запрос. Изменённый текст запроса помечается как неприменённый. Возврат сети/видимости инициирует догоняющую синхронизацию. При рабочем SSE и отсутствии событий health обновляется примерно раз в 15 секунд; при недоступном SSE остаётся fallback 2,5 секунды.

Live показывает последние 100 совпадений выбранного запроса. Историческая пагинация ставит отображение на паузу, UI ограничен 1000 строками. Все сохранённые события остаются в базе и доступны через уточнение запроса/экспорт. Пауза не останавливает collector/ingestion; выбранные детали не меняются при новых событиях.

Оптимизации: ленивый JSON, агрегации только для раскрытого графика, сохранение immutable rows по UID и `React.memo`, объединение push-бурстов, отсутствие конкурентных фоновых поисков и поиска в неактивном workspace, agent polling по 15-секундным epochs. Linux build повторно использует native `node_modules` при неизменном lock, уменьшая ненужный IO/Sysmon FileCreate при разработке.

## Фактические проверки

| Проверка | Результат |
|---|---|
| Windows / Linux Rust tests | 66 / 60 passed |
| Windows core/desktop clippy, fmt | Pass |
| UI lint, TypeScript, web/render/DSL/SSE decoder tests | Pass |
| Windows Sysmon → SSE → WebView без collect/refresh | Pass, последние замеры 1365 и 795 ms после готовности подписки |
| Пауза/догоняющее обновление/удержание деталей | Pass через реальные controls |
| Разрыв сети и возврат | Pass через CDP network emulation |
| SSE без API token | 401, Windows и Linux |
| Linux journald → SSE → GTK/WebKit UI | Pass, последние замеры 1134 и 938 ms |
| Linux GUI data | Финальный smoke: 1339 indexed events, 100 API/UI rows |
| Смена workspace | Нет скрытых event-search в «Источники»; возврат в «События» автоматически догоняет новый event |
| Single instance / Linux sidecar cleanup | Pass |
| 1440/1024 default layout | 100 real rows, без горизонтального overflow |
| Windows Audit preview | Read-only inspection; elevated операции не запускались |

795–1365/938–1134 ms — наблюдаемые отдельные end-to-end замеры, не p95/SLA. Windows smoke использует 1-minute initial history и новый диагностический process event; большой backfill — отдельная фаза загрузки. Linux smoke создаёт одну явно обозначенную diagnostic `logger` запись. Базы временные; runtime demo data отсутствуют.

Финальный Linux `ps rss` snapshot (`outputs/linux/report.json`): core 13440 KiB (~13 MiB), desktop/GTK 191400 KiB, WebKit web 446208 KiB, network 70512 KiB, journalctl 14080 KiB. Shared pages могут учитываться несколько раз; число событий отличается от предыдущего измерения, поэтому снижение RSS нельзя приписывать исключительно GUI-изменениям.

## Воспроизведение

```powershell
node scripts/smoke-desktop-ui.mjs --live-ui --filters
node scripts/smoke-desktop-ui.mjs --screenshot outputs/gui-after.png
node scripts/smoke-desktop-ui.mjs --screenshot outputs/gui-after-1024.png --viewport 1024
```

```bash
CARGO_TARGET_DIR=/path/to/redtrace-linux-target python3 scripts/smoke-linux.py
python3 scripts/smoke-desktop-linux.py --package outputs/linux/REDTRACE_0.1.0_amd64.deb --output outputs/linux
```

Порты 9710 и Windows WebView debugging 9225 должны быть свободны. Эти команды не включают Windows Audit, не меняют ACL и не устанавливают Sysmon.

## Артефакты и дальнейшие проверки

Windows: `src-tauri/target/release/bundle/nsis/REDTRACE_0.1.0_x64-setup.exe`, unsigned, около 3.25 MiB. Linux: `outputs/linux/REDTRACE_0.1.0_amd64.deb`, около 5.30 MiB, Kali rolling build.

Дальше: согласованный reliability gate, keyboard navigation по строкам/screen-reader UX. Представления и колонки реализованы в следующей итерации (`docs/VIEWS_AND_LOAD.md`). Виртуализация имеет смысл при увеличении UI-limit. Системная установка пакетов этой итерации и старые Linux distributions отдельно не проверялись; macOS runtime не запускался. Linux clippy component отсутствует; Linux compilation/tests выполнены. Sysmon/Windows ACL сохранены. Production-оценка: `docs/PRODUCTION_READINESS.md`.
