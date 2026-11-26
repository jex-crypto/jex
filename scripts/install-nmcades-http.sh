#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Install / refresh LaunchAgent for Safari HTTP bridge (127.0.0.1:18787).
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
HOST_SH="$ROOT/extension/host/jex-nmcades-http.sh"
LABEL="ru.jex.nmcades-http"
PLIST="$HOME/Library/LaunchAgents/${LABEL}.plist"
LOG_OUT="$HOME/Library/Logs/jex-nmcades-http.out.log"
LOG_ERR="$HOME/Library/Logs/jex-nmcades-http.err.log"

chmod +x "$HOST_SH" "$ROOT/scripts/ensure-nmcades-http.sh"
mkdir -p "$HOME/Library/LaunchAgents" "$(dirname "$LOG_OUT")"

UID_NUM="$(id -u)"
DOMAIN="gui/${UID_NUM}"

# Unload previous if present.
if launchctl print "${DOMAIN}/${LABEL}" >/dev/null 2>&1; then
  launchctl bootout "${DOMAIN}/${LABEL}" 2>/dev/null || true
fi

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>${LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>${HOST_SH}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>2</integer>
	<key>StandardOutPath</key>
	<string>${LOG_OUT}</string>
	<key>StandardErrorPath</key>
	<string>${LOG_ERR}</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>JEX_NMH_NO_UI</key>
		<string>1</string>
	</dict>
</dict>
</plist>
EOF

launchctl bootstrap "$DOMAIN" "$PLIST" 2>/dev/null || launchctl load "$PLIST"
launchctl kickstart -k "${DOMAIN}/${LABEL}" 2>/dev/null || true
echo "installed LaunchAgent $PLIST"
echo "bridge: http://127.0.0.1:18787/  (curl -s http://127.0.0.1:18787/)"
