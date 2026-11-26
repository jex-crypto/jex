#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Ensure LaunchAgent ru.jex.nmcades-http is loaded and running (Safari HTTP bridge).
set -eu
LABEL="ru.jex.nmcades-http"
UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"
# Prefer bootstrap if not loaded; always kickstart.
if ! launchctl print "${DOMAIN}/${LABEL}" >/dev/null 2>&1; then
  PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
  if [ -f "$PLIST" ]; then
    launchctl bootstrap "$DOMAIN" "$PLIST" 2>/dev/null || launchctl load "$PLIST" 2>/dev/null || true
  fi
fi
launchctl kickstart -k "${DOMAIN}/${LABEL}" 2>/dev/null || true
