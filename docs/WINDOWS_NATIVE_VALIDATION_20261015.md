# Windows native validation — 15 октября 2026

Проверен текущий код 0.2.0 на Windows 11 Pro x64: Rust 1.95.0, target `x86_64-pc-windows-msvc`, Node.js 24.13.1. Исходники перенесены из Git bundle коммита `03996f8` с проверкой SHA-256; исправления ниже применены к отдельной копии. Существующая рабочая копия и запущенный collector сохранены.

## Исправления, найденные при запуске

- При первом portable-запуске Windows WAL создавал каталог с унаследованным DACL, после чего control plane отвергал его как недостаточно приватный. Новый каталог данных теперь создаётся через общий механизм private-directory до открытия WAL. Проверка ошибочных query settings по-прежнему предшествует созданию каталога.
- Тестовые данные для query/control и WAL recovery получают приватный каталог с каноническим родительским путём. Это сохраняет Windows DACL и учитывает системные symlink-пути временного каталога на macOS.
- Query API и Windows core/agent TLS test используют свободные локальные порты. На машине одновременно работал другой collector на 9710; тесты не обращаются к нему.
- Backup fixture на Windows сохраняет Linux audit source path в POSIX-формате; перенос Windows module/service paths проверяется отдельно. На Unix сохраняется проверка переноса собственного audit path.

## Результат

| Проверка | Результат |
|---|---|
| Windows `cargo test --locked --all-targets --no-fail-fast` | 260 passed, 0 failed, 3 ignored |
| Три ignored read-only native Event Log probes, запущенные отдельно | 3 passed, 0 failed |
| Windows и macOS Rust fmt / Clippy all-targets с `-D warnings` | PASS |
| macOS `cargo test --all-targets` после исправлений | 246 passed, 0 failed |
| Windows npm ci, ESLint, TypeScript, web build и UI tests | PASS, 17 UI tests |
| Windows MSVC release core/agent/helper и desktop NSIS build | PASS |

Native probes прочитали реальные каналы: multi-channel stream доставил 2531 запись в тестовый receiver, проверены завершение подписки и повторное открытие Sysmon bookmark. Отдельный regression probe воспроизвёл известный Windows API error 4317 при неправильном повторном `EvtNext`; это проверка защитного сценария, а не ошибка рабочего stream. Durable checkpoints рабочего collector не изменялись. Windows process TLS test подтвердил доставку исторических native events через отдельные core/agent процессы; генерация нового события после старта этим тестом не проверяется.

Пересобран unsigned installer `REDTRACE_0.2.0_x64-setup.exe`: **5 517 216 bytes**, SHA-256 `bd73af4c3d6baceee310a4059c65c3405868927c0bc87795e912df0cd92750d0`.

Пакет находится в `C:\Users\Nikita\Documents\REDTRACE-validation-20261015\repo\src-tauri\target\release\bundle\nsis`. Логи и manifest сохранены на Windows в родительском validation-каталоге и локально в `outputs/windows-validation-20261015`.

## OpenCode

Обе сессии ревью выполнены через установленный OpenCode 1.18.25 с явной моделью `openai/gpt-6.1-sol`, variant `medium`, сохранённой OpenAI OAuth-авторизацией и процессными `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` = `http://127.0.0.1:1080`. `NO_PROXY` включает loopback. Реальный inference smoke вернул `OPENAI_PROXY_OK`. Для наших задач main и small model закреплены на той же OpenAI-модели; секреты в отчёт и репозиторий не включены.

## Оставшиеся границы

Новый GUI проверен отдельным этапом: [25 GUI checks и визуальное ревью](WINDOWS_GUI_VALIDATION_20261015.md). Установка/удаление NSIS, SCM start/stop/reboot и длительный soak не подтверждены. Существующий collector восстановлен после GUI-проверки. Политики аудита, Sysmon и ACL рабочих Event Log каналов не менялись.

Два source-review отчёта OpenCode сохранены в `outputs/windows-validation-20261015/*-review.english.jsonl`. Они отделены от результатов исполнения. В них отмечены вопросы для следующей проверки: права service handle при настройке restart recovery, защита существующего spool при enrollment, восстановление после неполного enrollment, управление повреждённой service installation, ownership scheduled tasks, renewal возле срока CA, хранение скачанных backup, актуальность installer smoke, fairness Windows channels и XML/PID/checkpoint normalization. Эти замечания не считаются закрытыми успешным прогоном существующих тестов и требуют отдельных регрессий и проверки исправлений.
