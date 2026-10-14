# WAL recovery / rotation — 12.10.2026

## Закрытый дефект

В рабочем `active.wal` размером 17 515 326 bytes была одна невалидная строка: строка 2086, byte offset 2379461, length 1127. В ней обнаружен оборванный JSON prefix длиной 357 bytes и следующий полный WAL record длиной 769 bytes с правильной version/checksum. UID полного record: `b5157b0a0924b2b7`.

Старый `append` дописывал прямо после EOF без проверки newline, а `recover` пропускал всю невалидную строку. Таким образом, новый полный record мог быть потерян при replay, несмотря на успешную запись/ACK. Наличие повреждения также запрещало startup migration и каждую следующую rotation. Forced kill на закрытии desktop мог оборвать поэлементную JSON-запись; точный момент исходного interruption независимо не установлен.

## Реализация

- Каждый WAL record сначала сериализуется в один buffer вместе с newline и записывается `write_all`, затем batch получает `sync_data` перед ACK.
- Перед append проверяется последний byte; неполная предыдущая строка отделяется newline от новых records. Полный record без newline также сохраняется.
- Cloned writers используют общий mutex. Отдельный ownership lock file предотвращает запуск второго cooperating collector с тем же WAL до любых recovery/migration. Lock сохраняется при замене/reset active file и освобождается после закрытия всех handles процесса. Минимальный Rust — 1.89; проверено Windows 1.95 / Linux 1.99.
- Read-only recovery умеет найти serialized record boundaries внутри malformed line и принимает только полностью десериализуемые records с поддерживаемой version и правильной checksum. Parsed records с плохой checksum/неизвестной version не считаются надёжными.
- Startup и rotation используют `recover_with_repair`: полный исходный WAL копируется и синхронизируется в `wal-quarantine/<id>.wal`; report сохраняет byte ranges/reasons и counters без event content. Проверяется размер/fingerprint источника и архива. Canonical clean WAL пишется отдельно, синхронизируется и публикуется rename только после сохранения evidence.
- Reader I/O errors возвращаются как ошибки и не выдаются за повреждение. Ошибка архивирования/квота/изменившийся источник оставляют original WAL нетронутым. В main startup такой отказ завершает процесс до collectors/ingest.
- Архивирование ограничено 256 MiB суммарно; report — до 64 KiB, samples — до 64. При исчерпании бюджета автоматическое восстановление отказывается продолжать, без удаления evidence. Архивы не удаляются retention автоматически.
- В Unix quarantine directory — 700, files — 600. На Windows наследуются права защищённого data directory. Quarantine path не должен быть symlink/обычным файлом; temp files создаются exclusive и cleanup касается только созданных этой операцией файлов.
- Active RAM index при startup строится только из WAL UIDs, которых нет в segments, чтобы recovery overlap не добавлял повторный счёт.
- Health и diagnostics показывают текущую целостность отдельно от архивной истории. В GUI «Источники → Целостность» видны архивы восстановления.

Fingerprint встроенного repair — существующий FNV-1a64 integrity checksum, не cryptographic authenticity. SHA-256 forensic comparison выполнялась отдельно. Ownership lock защищает cooperating collectors, не произвольные сторонние filesystem tools. Power-loss/disk-full/мультихостовые reliability gates этой итерацией не закрываются.

## Evidence и реальные данные

До deployment рабочая база не менялась. При остановленном core сохранены original WAL, catalog/checkpoints и inspection report в `%LOCALAPPDATA%\REDTRACE\wsl-pilot\wal-evidence-20261009`. Имя каталога историческое; snapshot этой итерации сделан 12.10.2026. SHA-256:

```text
d3ed2e5864d872b87b01197b71c9eff8f3c6482d5889a8d3773c7353a3920f1f
```

Отдельная WAL-only working copy проверена примером `recover-wal-copy`: 15 174 обычных valid records + 1 checksum-valid merged record → **15 175 unique UIDs**, все сохранены после segment commit и WAL reset. Input evidence не изменялась.

На рабочей базе новый core сохранил оригинал в `%LOCALAPPDATA%\REDTRACE\wal-quarantine\b05fe0e700c6be14.wal`. Независимая повторная inspection этого архива дала тот же SHA-256. Startup: **77931 recovered UIDs**, corrupted WAL/segments/indexes = **0**. UID `b5157b0a0924b2b7` найден в настоящем GUI ровно один раз.

После восстановления native GUI diagnostics:

| Counter | Значение |
|---|---:|
| corrupted_wal_records | 0 |
| corrupted_segments / indexes | 0 / 0 |
| wal_errors / segment_errors / checkpoint_errors | 0 / 0 / 0 |
| wal_quarantine_archives | 1 |
| quarantined_wal_records | 1 |
| salvageable_wal_records | 1 |

Оборванный prefix не имеет полной checksum-valid записи: его байты сохранены, содержимое не выдумывается. Исправление подтверждает сохранность проверенных records, не доказательство восстановления неизвестного/уже повреждённого содержимого.

## Проверки

- **83 Windows / 77 Linux Rust tests**: framing torn/unterminated tails, merged salvage, exact-byte archive, checksum/version/UTF-8 rejection, quota/archive failure preservation, ownership/reset lifetime, concurrent cloned writers.
- Process regression `tests/wal_recovery.rs`: repaired startup, original archive equality, отказ второго collector, 1000 ACK fixtures, подтверждённая rotation, force kill/restart, **1000/1000 recovered**, replay = **1000 duplicates**, новых records нет.
- Windows core/desktop clippy и fmt — PASS. Linux clippy component отсутствует; не устанавливался.
- UI TypeScript, targeted ESLint, web/desktop UI builds и полный набор **16 Node tests** — PASS. Реальное Windows окно: restored UID, keyboard/mouse autocomplete, dropdown scroll, свежий Kali `logger` event после resume — PASS.
- Пересобран только Windows release core и заменён pilot sidecar с hash verification; предыдущий executable сохранён в защищённом pilot directory. Desktop frontend работает через Vite 1420/hot reload; shell/NSIS/Linux packages не пересобирались.

## Инструменты

```powershell
node scripts/wsl-pilot.mjs status
```

Inspection utility работает read-only с WAL и опционально создаёт новые snapshots/working copies; печатает только counters/offsets/hashes, не сообщения:

```text
python scripts/inspect-wal.py <wal> --snapshot <new-private-directory>
python scripts/inspect-wal.py <immutable-copy> --working-copy <new-private-directory>
cargo run --locked --example recover-wal-copy -- <working-copy>/active.wal
```

Example отказывается работать в существующей базе с `catalog.json`; использует только отдельную WAL-only copy. `scripts/deploy-pilot-core.mjs` заменяет только остановленный pilot core, сохраняет старый executable и проверяет SHA-256. Не повторять setup/PKI ради core/UI правки.

Итог: конкретный blocker WAL replay/rotation исправлен и проверен на рабочей базе. Service lifecycle, retention age/cap, bounded query execution/ingest/collectors, signing и согласованный long reliability gate остаются в implementation plan. Sysmon/ACL/firewall не менялись, long tests не запускались, commit/push не выполнялись.
