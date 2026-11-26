#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# HTTP bridge for Safari Web Extension (127.0.0.1:18787).
# Used by LaunchAgent ru.jex.nmcades-http — not by Chrome stdio NMH.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
JEX="${JEX:-$ROOT/target/release/jex}"
if [ ! -x "$JEX" ]; then
  JEX="$ROOT/target/debug/jex"
fi
CONFIG="${JEX_DAEMON_CONFIG:-$ROOT/examples/daemon.json}"
LISTEN="${JEX_NMH_HTTP:-127.0.0.1:18787}"
export JEX_NMH_NO_UI="${JEX_NMH_NO_UI:-1}"
LOG="${JEX_NMH_HTTP_LOG:-$HOME/Library/Logs/jex-nmcades-http.log}"
mkdir -p "$(dirname "$LOG")"
echo "$(date '+%Y-%m-%dT%H:%M:%S') start jex=$JEX listen=$LISTEN" >>"$LOG"
# Drop stale listener (previous agent / Jex.app child).
/usr/bin/pkill -f "nmcades-host --config .* --http ${LISTEN}" 2>/dev/null || true
sleep 0.2
exec "$JEX" nmcades-host --config "$CONFIG" --http "$LISTEN" 2>>"$LOG"
