#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
set -eu
rm -f "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts/ru.jex.nmcades.json"
rm -f "$HOME/Library/Application Support/Chromium/NativeMessagingHosts/ru.jex.nmcades.json"
rm -f "$HOME/Library/Application Support/Microsoft Edge/NativeMessagingHosts/ru.jex.nmcades.json"
rm -f "$HOME/Library/Application Support/Mozilla/NativeMessagingHosts/ru.jex.nmcades.json"
echo "removed ru.jex.nmcades manifests (user)"

LABEL="ru.jex.nmcades-http"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"
if launchctl print "${DOMAIN}/${LABEL}" >/dev/null 2>&1; then
  launchctl bootout "${DOMAIN}/${LABEL}" 2>/dev/null || true
fi
rm -f "$PLIST"
/usr/bin/pkill -f "nmcades-host --config .* --http 127.0.0.1:18787" 2>/dev/null || true
echo "removed LaunchAgent ${LABEL}"
