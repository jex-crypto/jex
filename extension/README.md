# Jex browser extension

Own extension + Native Messaging host **`ru.jex.nmcades`** (does not replace CryptoPro).

Official CryptoPro demos load only
`chrome-extension://pfhgbfnn…/nmcades_plugin_api.js`. Jex **rewrites** those
script URLs to its own API file, so demos work without a patched
`cadesplugin_api.js`. Prefer **disabling** the CryptoPro Chrome extension while
testing Jex (both can answer `postMessage` otherwise).

## Install (macOS)

```bash
cargo build --release
./scripts/install-extension-host.sh
```

Chrome → `chrome://extensions` → Developer mode → **Load unpacked** →
`extension/chrome` → click **Reload** after code updates.

Stable extension id: `ogfkpliagdeofggffdpifnakdhgfiagc`.

Firefox (MV2, id `jex@jex.local`): `about:debugging#/runtime/this-firefox` →
**Load Temporary Add-on** → `extension/firefox/manifest.json`. After updates use
**Reload**. Disable CryptoPro’s Firefox extension while testing. NMH must list
`allowed_extensions: ["jex@jex.local"]` (re-run `install-extension-host.sh`).

Safari: see [`safari/README.md`](safari/README.md). HTTP bridge is a LaunchAgent
(`scripts/install-nmcades-http.sh`); the Safari appex cannot spawn NMH itself.

## Behaviour

- `cadesplugin` / CAdESCOM → this extension → `jex nmcades-host`
- Unknown site → egui trust dialog; PIN prompts on unlock
- Headless: `JEX_NMH_NO_UI=1`

## Uninstall

```bash
./scripts/uninstall-extension-host.sh
./scripts/restore-cryptopro-nmcades.sh   # only if system nmcades was swapped
```
