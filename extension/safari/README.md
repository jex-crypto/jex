# Safari Web Extension

Safari **не** поднимает Native Messaging host сам (в отличие от Chrome
`connectNative`). Мост — локальный HTTP `127.0.0.1:18787`, его держит
**LaunchAgent** `ru.jex.nmcades-http`. Расширение при недоступности моста
просит appex сделать `launchctl kickstart`.

## Как пользоваться

1. Один раз:
   ```bash
   cargo build --release
   ./scripts/install-extension-host.sh   # NMH + LaunchAgent HTTP
   # или только мост:
   ./scripts/install-nmcades-http.sh
   ```
2. Develop → **Allow Unsigned Extensions** (после рестарта Safari).
3. Extensions → **Jex** On → **Allow on Every Website**.
4. CryptoPro Safari extension — Off.
5. Окно Jex.app **не обязательно** держать открытым (мост = LaunchAgent).
6. Обновите демо.

Проверка моста:

```bash
curl -s http://127.0.0.1:18787/
# → jex nmcades-host ok

launchctl print gui/$(id -u)/ru.jex.nmcades-http | head
```

Логи: `~/Library/Logs/jex-nmcades-http.log` (+ `.out.log` / `.err.log`).

## Сборка

```bash
cargo build --release
./scripts/install-nmcades-http.sh
open extension/safari/Jex/Jex.xcodeproj   # Run схему Jex (включить extension)
```

После каждого ad-hoc Run UUID appex меняется — `AppDelegate` / `sync-safari-nmh.sh`
обновляет `~/Library/Safari/NativeMessagingHosts/ru.jex.nmcades.json` (нужно
только если снова включите stdio NMH; для HTTP-моста не критично).
