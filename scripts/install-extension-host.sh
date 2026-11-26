#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Install ru.jex.nmcades for Chrome (+ Chromium/Edge user dirs) and restore CryptoPro system nmcades.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
HOST_SH="$ROOT/extension/host/jex-nmcades-host.sh"
TEMPLATE="$ROOT/extension/host/ru.jex.nmcades.json.template"
EXT_ID="${JEX_EXTENSION_ID:-ogfkpliagdeofggffdpifnakdhgfiagc}"
BACKUP="/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades.cryptopro.bak"
NMCADES="/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades"

chmod +x "$HOST_SH"

install_nmh() {
  dir="$1"
  mkdir -p "$dir"
  out="$dir/ru.jex.nmcades.json"
  sed -e "s|JEX_NMH_PATH_PLACEHOLDER|$HOST_SH|g" \
      -e "s|ogfkpliagdeofggffdpifnakdhgfiagc|$EXT_ID|g" \
      "$TEMPLATE" >"$out"
  echo "installed $out"
}

install_nmh "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
install_nmh "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
if [ -d "$HOME/Library/Application Support/Microsoft Edge" ]; then
  install_nmh "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts"
fi

# Firefox uses allowed_extensions — write a sibling template if gecko id present
FF_TEMPLATE="$ROOT/extension/host/ru.jex.nmcades.firefox.json.template"
if [ -f "$FF_TEMPLATE" ]; then
  ffdir="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
  mkdir -p "$ffdir"
  sed -e "s|JEX_NMH_PATH_PLACEHOLDER|$HOST_SH|g" "$FF_TEMPLATE" >"$ffdir/ru.jex.nmcades.json"
  echo "installed $ffdir/ru.jex.nmcades.json"
fi

# Safari Web Extension NMH (needs safari-web-extension://UUID/)
"$ROOT/scripts/sync-safari-nmh.sh" || true

# Safari HTTP bridge (appex cannot launch NMH; LaunchAgent KeepAlive)
"$ROOT/scripts/install-nmcades-http.sh" || true

# Restore CryptoPro system binary if we previously replaced it
if [ -e "$BACKUP" ] && head -1 "$NMCADES" 2>/dev/null | grep -q '^#!/bin/sh'; then
  echo "Restoring CryptoPro system nmcades from backup…"
  osascript <<APPLESCRIPT
do shell script "cp -p '$BACKUP' '$NMCADES' && chmod 755 '$NMCADES'" with administrator privileges
APPLESCRIPT
  echo "CryptoPro nmcades restored."
fi

# Remove hijacked Chrome user cryptopro host if it points at jex
CP_USER="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/ru.cryptopro.nmcades.json"
if [ -f "$CP_USER" ] && grep -q 'jex' "$CP_USER"; then
  rm -f "$CP_USER"
  echo "removed user ru.cryptopro.nmcades.json (was pointing at jex)"
fi

echo
echo "Load unpacked extension from: $ROOT/extension/chrome"
echo "Extension id (stable key): $EXT_ID"
echo "Then reload the extension / restart Chrome."
