# M1 — бюджеты query parser

Дата: 08.10.2026. Итерация реализует первый code item из `IMPLEMENTATION_PLAN.md`.

## Поведение

| Бюджет | Default / максимальное разрешённое значение | Настройка |
|---|---:|---|
| Размер исходного запроса | 8192 UTF-8 байта | `REDTRACE_QUERY_MAX_BYTES` |
| Токены | 256 | `REDTRACE_QUERY_MAX_TOKENS` |
| Вложенность | 16 | `REDTRACE_QUERY_MAX_DEPTH` |
| Узлы AST | 64 | `REDTRACE_QUERY_MAX_NODES` |

- Размер проверяется перед созданием lexer buffers, включая пустой/whitespace/match-all запрос. Размер относится к декодированному `q`, а не percent-encoded URL.
- Токены включают слова, quoted literals, операторы и скобки. Quoted literal — один токен; его размер ограничен общим byte budget. Lexer отклоняет следующий токен до его создания.
- Каждая открытая скобка и каждый `NOT` расходуют один общий уровень на текущем recursive path. Проверка выполняется до рекурсивного вызова. Закрытые соседние группы не накапливают depth.
- Каждый leaf, `NOT`, `AND` и `OR` расходует один AST node. Binary/unary node резервируется до разбора следующего operand и выделения `Box`; глубина boolean chains также ограничена общим числом узлов.
- Пустой запрос и одиночный `*` дают один `MatchAll`; каждый разрешённый node budget не меньше 1. Скобки не создают AST nodes, но расходуют depth/token budgets.
- Настройки допускают только целые значения от 1 до указанных ceilings. Ноль, неизвестный формат, non-UTF-8 и превышение ceiling останавливают startup с кодом 2 до открытия базы/collectors. Запросы с неверными custom `QueryLimits` также отклоняются.
- `parse()` использует default limits; серверные search/aggregations/export вызывают `parse_with_limits()` с startup-настройками. Настройки не перечитываются в середине запроса.
- Ошибки parser возвращают HTTP 400: `error`, `offset`, `limits`, совместимое поле `max_nodes`. `offset` — реальная позиция в исходном UTF-8 запросе в байтах, а не индекс токена/символа; EOF равен длине строки. При byte overflow позиция округляется к ближайшей границе символа справа от лимита.
- `/api/health` и `/api/diagnostics` содержат `query_limits`.

Числа — консервативные engineering ceilings этой alpha-итерации, подтверждённые boundary tests. Они не задают SLA search latency, RAM или пропускной способности; один разрешённый contains-запрос всё ещё может быть дорогим на большой базе.

## Проверки

`src/query.rs`: новые unit fixtures проверяют byte boundary с ASCII/кириллицей/whitespace, token boundary с операторами, разрешённую и запрещённую глубину parentheses/NOT/combined, malformed глубокий запрос, границы AST nodes с AND/OR, все типы leaf, UTF-8 error offsets, escaped quotes/Windows backslashes и fail-closed конфигурацию. Существующие precedence/index/postings tests сохранены.

`tests/query_api.rs` запускает отдельный core с временной базой и случайным session token, предварительно сохраняет один явно обозначенный fixture в WAL. Startup переносит fixture в дисковый сегмент. Сниженные budgets 1024 bytes / 128 tokens / 8 depth / 32 nodes проверяются через настоящий HTTP API:

- Search, aggregations и export: по 6 oversized/too-deep/too-complex/syntax cases возвращают ожидаемые JSON 400 и byte offsets.
- После отказов каждый endpoint выполняет по 5 валидных exact/contains/existence/exclusion/nested/boolean запросов к контрольной записи: поиск и агрегации дают ровно 1 совпадение, JSONL export — исходный UID.
- Health/diagnostics показывают фактические startup budgets; запрос без токена возвращает 401.
- Неверный depth config завершает отдельный процесс кодом 2 и не создаёт каталог базы.
- Процесс и временная база очищаются RAII guard; контрольные события не попадают в рабочую базу.

Результаты:

| Проверка | Результат |
|---|---|
| Windows `cargo test --all-targets --locked` | **74 passed**: 63 lib + 1 core + 7 ingest + 1 query API + 1 TLS + 1 native Windows core/agent TLS process |
| Kali WSL `cargo test --all-targets --locked` | **68 passed**: 58 lib + 1 core + 7 ingest + 1 query API + 1 TLS |
| Windows `cargo fmt --check` | PASS |
| Windows core/desktop `cargo clippy … -- -D warnings` | PASS |
| UI ESLint / TypeScript / web и desktop UI builds / Node tests | PASS / PASS / PASS / **9 passed** |
| Linux clippy | Не выполнен: component отсутствует; системные инструменты не устанавливались |

Windows UI-команды вызваны через `npm.cmd`/`npx.cmd`: PowerShell execution policy блокирует `npm.ps1`. Первый ESLint run превысил 120s tool timeout; отдельный повтор с увеличенным timeout завершился успешно. Это не нагрузочный/soak тест. Linux core/tests используют отдельный `CARGO_TARGET_DIR` в разрешённом Temp/opencode; Windows и Linux artifacts не смешиваются.

## Граница этапа и дальнейшая работа

Parser-budget item M1 закрыт. Bounded search/top-k/cancellation/concurrency, согласованный RAM/disk snapshot, ingest quotas/metadata, bounded Linux follow и retention age/cap остаются в `IMPLEMENTATION_PLAN.md`.

Длинные load/soak тесты не выполнялись. Sysmon, channel ACL, audit policy и registry этой итерацией не изменялись. Эта итерация подтверждена исходниками, debug core process tests и desktop compilation/clippy; реальные GUI и NSIS/`.deb` относятся к предыдущему milestone, пакеты этой итерацией не пересобирались. Production verdict остаётся закрытой alpha / read-only pilot.
