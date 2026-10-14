# Базовый статус и подсказки фильтров — 09.10.2026

## Итог

Обновление 12.10.2026: описанный ниже WAL blocker исправлен и проверен на рабочей базе. Current diagnostics: corrupted WAL/segments/indexes = 0, WAL/segment/checkpoint errors = 0. Историческая строка сохранена в quarantine; один checksum-valid record из склеенной строки восстановлен. Подробности: `WAL_RECOVERY.md`. Ниже — исходный срез 09.10.2026, а не актуальные counters после repair.

Базовый контур Windows/Kali WSL → collector → WAL/index → поиск → live GUI работает в контролируемом пилоте. Полностью штатным и production-ready состояние пока не является: обнаруженная повреждённая запись WAL препятствует rotation. База не очищалась и не ремонтировалась в этой UI-итерации.

| Область | Подтверждённый статус |
|---|---|
| Windows native collection | Работает в существующем desktop-owned core |
| Kali WSL agent / HTTPS | Запущен, доверенный CA/SAN, heartbeat и ACK/checkpoint работают |
| Поиск, exact/contains/existence, исключения | Работают; parser budgets реализованы предыдущей итерацией |
| Live GUI, pause/resume | Свежая diagnostic journald-запись появилась в настоящем Windows WebView после resume |
| Представления, колонки, детали, экспорт | Реализованы; предыдущие GUI проверки и актуальные UI tests проходят |
| Детекты / алерты | Реализованы, покрыты предыдущими Rust/GUI проверками; новая атака для их проверки в этой итерации не генерировалась |
| Storage | Degraded: native GUI diagnostics подтверждают 1 corrupted WAL record, 50 segment errors, 0 WAL append errors и 0 checkpoint errors на момент снимка. Corrupted segments/indexes — 0. Нулевой WAL-error counter не доказывает сохранность повреждённой записи |
| Без открытого GUI / после reboot | Windows Service/systemd lifecycle и durable disk outbox пока не реализованы; закрытие desktop завершает core |

Следующий приоритет надёжности — сохранить backup/evidence WAL, определить повреждённую запись и причину, затем реализовать безопасное recovery/rotation с regression fixtures. Не обнулять WAL и не обещать отсутствие потерь подтверждённых записей без проверки. Signing, query execution/retention/ingest budgets и длительный reliability gate остаются в `IMPLEMENTATION_PLAN.md`.

## Подсказки

- В `Добавить фильтр`: имена стандартных/наблюдавшихся полей и значения выбранного поля. `Существует` по-прежнему не требует значения.
- В DSL-строке: field completion с `=`, затем actual value completion с кавычками/escaping. Работают `=`, `~`, legacy `:`, скобки, NOT, AND/OR и редактирование в середине запроса; остаток запроса сохраняется.
- В contains-режиме: подходящие реальные значения без вставки DSL-операторов. Compiled query использует существующее безопасное quoting.
- Совпадения без учёта регистра, prefix matches выше substring matches. Мышь или `↑`/`↓` + Enter; Esc закрывает только подсказки. Выбор не запускает поиск сам по себе.
- Поле имеет ARIA combobox/listbox/option semantics; активный вариант прокручивается внутри списка, без прокрутки event stream. Отложенная установка caret не перехватывает фокус и не отменяет выделение текста.
- Значения ограничены показанным окном: до 200 events, 256 fields, 100 уникальных values на field, до 512 characters на value; dropdown — до 12 вариантов. Empty/`н/д` не выдаются за реальные значения. Это не серверный словарь всей базы.
- Каталог memoized, без запросов API на каждую клавишу. Map используется для prototype-like field names; UI рендерит значения обычным React-текстом, без HTML injection.

## Проверки

- TypeScript и ESLint затронутых файлов — PASS.
- `npm test` — web build + **16 passed** Node tests, включая 7 новых suggestion fixtures: matching/ranking, реальные значения, prototype-like fields, literal contains, nested/mid-query DSL, Windows paths/quotes, boolean-looking literals, bounds.
- `npm run desktop:ui:build` — PASS. Rust/Tauri release и installers не пересобирались; изменения доступны в работающем Vite dev frontend 1420 через hot reload.
- Native Windows UI Automation с реальными keyboard/mouse actions: contains completion, field/value в filter builder, DSL field/value, Esc, pointer selection — PASS. Filter form применён к настоящим событиям, свежий `logger --tag redtrace-suggestions-check` marker прошёл агент→HTTPS→core→GUI. Явно обозначенная diagnostic запись остаётся в system journal.
- При проверке каталог был зафиксирован штатной паузой отображения; сбор продолжался, затем live возобновлён. Это предотвращает изменение suggestion samples во время keyboard assertion.
- Итоговый GUI: 100 Linux rows, `agent.name="kali-wsl"`, 6197 matches в последнем снимке. Это счётчик query snapshot, не независимая lifetime-проверка каждого ACK event.
- Запущены desktop PID 10348, core PID 26008, Linux agent PID 296, frontend PID 21248 и WSL keeper; PID могут измениться. Окно и процессы оставлены работающими. `node scripts/wsl-pilot.mjs status` подтверждает TLS ingest и agent activity.

Системные политики, Sysmon, Windows channel ACL и firewall не менялись. Коммит/push не выполнялись. Текущие credentials/PKI остаются в защищённых pilot directories вне исходников.
