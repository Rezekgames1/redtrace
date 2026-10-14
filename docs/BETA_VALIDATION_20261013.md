# Early beta validation — 2026-10-13

## Исправления

- Независимый от retention durable receipt log: checksum/version, bounded 65 536 UID / 24 h / 4 MiB, replay после restart и quarantine torn original. Main записывает receipts после WAL sync и до rotation, включая startup migration. При окончательном отказе consumer есть explicit `storage_rejected`; рабочий main сохраняет/retry failed batch.
- Checkpoint sequence разрешает equal-timestamp ties; spool sequence переносится в collection/ACK checkpoint. Checkpoint state публикуется в RAM после успешного disk commit.
- Detection correlation/suppression разделены по authenticated agent ID; expiration управляется receiver monotonic time. Global/per-agent key/byte caps и refused counters видны в diagnostics.
- macOS NDJSON ограничен по record/batch bytes, native timestamps переведены в RFC3339 UTC, `sshd-session` поддерживается, boot/mach identity сохраняет разные записи. Проверка local process/listener identity на macOS добавлена через libproc/lsof.
- UI/API time range для search, paging, aggregation, export; local datetime inputs → UTC, start inclusive / end exclusive. Presets: all, 15m, 1h, 24h, 7d, custom.

## Прикладные проверки

Windows: 144 library tests PASS, 3 native tests оставлены ignored; 11 main tests PASS. Spool 25, ingest 7, ingest limits 10, TLS 1, service mode 6, critical integration 6, detection limits 3 PASS. После time feature повторно проверены затронутые library/main/integration/service cases. Core fmt/clippy и desktop clippy PASS; UI TypeScript/ESLint/desktop build PASS, 16 focused Node tests PASS.

MacBook Air arm64 / macOS 26.6.2 / Rust 1.95: до последнего time-filter добавления 128 library, 10 main, 25 spool, 3 detection, 6 hardening, 7 ingest, 10 limits, 6 service, 1 TLS PASS; native clippy PASS. `std::env::temp_dir` tests исправлены на canonical paths: `/var` является системным redirect на macOS, production path redirect validation не ослаблена. macOS GUI/package boot validation не выполнялась.

## Настоящий LAN test

Final package checks: Linux/Kali 131 library, 11 main и 6 hardening tests PASS. В retention fixture убрана нулевая TTL, чтобы commit не успевал evict сам fixture между соседними секундами; expiry задаётся явно в test catalog. Mac release core/agent/service binaries собраны arm64; native final time-range tests 3 library + 1 main PASS. Windows packaged release smoke через HTTP: 4 isolated events → 2 в time range; search/paging/aggregation/export PASS, invalid timestamp→400. Ни один fixture не записывался в рабочую базу.

Mac `192.168.31.216` → Windows `192.168.31.96:19711`, прямой HTTPS без SSH tunnel. Отдельные test CA, agents и базы; API на ephemeral loopback port. Initial 66 records; fresh SSH activity видна через 7.377 s; перед restart наблюдались 103 UID. После остановки collector 35 events durable spooled; agent force-kill; collector и agent restarted: 144 records, все 103 прежних UID сохранены, spool pending=0. Bad token→401, absent CA→certificate rejection. Storage/error counters 0. Это короткий end-to-end case, не long-soak/SLA.

Полный локальный report: protected `%LOCALAPPDATA%/Temp/opencode/redtrace-network-31a10db344c3e73c/report.json`. Первый basic pass: `redtrace-network-67eedeaee3fc249b/report.json`. Fixture core/agent завершены. Temporary Windows rule `REDTRACE-MacBook-Isolated-Test-19711` удалено и отсутствие проверено. Working 9710/9711 SIEM не перезапускался. Тестовый SSH public key помечен `redtrace-macbook-temporary`; cleanup command находится в `scripts/macbook-ssh.py`.

## Ресурсы

10.016 s sample старой живой Windows-сборки: core WS 408.62 MiB/private commit 882.75 MiB; весь process tree WS 717.87 MiB/private commit 1193.99 MiB; CPU 0.147% машины / 18 logical processors. Core CPU 1.716% одного ядра. macOS agent short startup/backfill RSS ~14 MiB; CPU snapshots 2.2–13.5% одного ядра. Значения не объявляются steady-load или resource SLA новой beta.

## Поставка

GUI delivery дополнена native Linux `.deb` и macOS arm64 `.dmg`. Linux package metadata содержит `/usr/bin/redtrace-desktop`, `/usr/bin/redtrace` и desktop menu entry; dependencies `libwebkit2gtk-4.1-0, libgtk-3-0`, размер 7 327 632 bytes. Реальный extracted-package GTK/WebKit smoke PASS: 2 907 indexed events, 100 GUI rows, journald→SSE→WebView marker 1 310 ms, missing token401, single instance и GUI close/core cleanup PASS. Отчёт: `outputs/beta-20261013/linux-gui-validation/report.json`.

macOS .app/.dmg собраны на arm64 Rust 1.95 из того же embedded frontend с явным `tauri/custom-protocol`; без Node.js на Mac. App включает desktop/core, Info.plist и icon.icns; ad-hoc codesign verify и hdiutil create прошли (это не publisher signing/notarization). Настоящий onscreen native window и authenticated frontend traffic подтверждены: 70 indexed native events, search100 limit вернул70, date/time filter PASS, missing token401, Apple Events GUI quit и owned core cleanup PASS. Native smoke report сохранён в protected Mac workspace `source/beta-desktop-output/gui-validation/report.json`; копия добавляется в beta outputs.

Temporary SSH key удалён локально и с MacBook после выгрузки arm64 release binaries. Working Windows listener остался на 127.0.0.1:9710 и прежнем WSL ingest 172.22.80.1:9711, PID 25076; beta installer не заменял работающий экземпляр автоматически.

Windows installer собран штатным Tauri CLI с embedded frontend, NSIS perMachine override и helper pin. Первая full build превысила 360 s tool timeout; resumed bundle build переиспользовал готовые sidecar/frontend, beforeBuildCommand отключён только в `tauri.beta-bundle.conf.json`. Результат NSIS — 4.06 MiB. Packaging script `scripts/package-beta.mjs` собирает доступные platform artifacts, инструкцию и SHA256 manifest в `outputs/beta-20261013/`.
