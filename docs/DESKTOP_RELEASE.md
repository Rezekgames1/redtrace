# Desktop release

RED//TRACE использует Tauri/Wry и отдельный Rust sidecar. Пользовательская установка не требует Node.js, npm или внешнего веб-сервера.

## Локальная проверка

```bash
npm ci
cargo test --all-targets
npm run lint
npm run desktop:build -- --no-bundle
```

`scripts/prepare-sidecar.mjs` определяет Rust target triple, собирает ядро и копирует его под именем, которое ожидает Tauri. Для cross-build target можно передать первым аргументом или через `TAURI_ENV_TARGET_TRIPLE`.

## Платформы

- macOS: `.app`/DMG, затем Developer ID signing, hardened runtime и notarization;
- Windows: NSIS/MSI, затем Authenticode для core, helper и установщика;
- Linux: deb/rpm/AppImage; подпись репозитория и checksum артефактов.

CI собирает unsigned package на каждой нативной ОС. Подписанные production-артефакты должны создаваться отдельным protected job с аппаратно или облачно защищёнными ключами. Ключи и сертификаты не хранятся в репозитории.

## Security boundary

Desktop shell создаёт 256-битный случайный токен для каждого запуска. Sidecar принимает API-запрос только с `x-redtrace-token`; UI получает токен через Tauri command. CSP запрещает произвольные сетевые назначения. Windows Audit apply не доступен через HTTP и должен выполняться отдельным подписанным privileged helper с узким allowlist.

## Известные ограничения текущей сборки

- нативные installers пока не подписаны и не notarized;
- native Windows Event Log subscription/bookmarks реализованы; `wevtutil` — явный fallback;
- Windows dev Audit helper реализован, production signing/trust gate остаётся открытым; auto-update ещё не реализован;
- Windows и Linux WSLg packages прошли документированные проверки, но отдельные physical hosts/minimum distro/upgrade matrix требуют дополнительных gates;
- persistent service/daemon mode пока отсутствует: portable desktop закрывает core при выходе.

План service lifecycle, signing, platform matrix и обновлений: `docs/IMPLEMENTATION_PLAN.md` (M3, M8). Текущая оценка: `docs/PRODUCTION_READINESS.md`.
