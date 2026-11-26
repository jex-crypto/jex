#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Native Messaging host wrapper for Jex (ru.jex.nmcades).
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"
JEX="${JEX:-$ROOT/target/release/jex}"
if [ ! -x "$JEX" ]; then
  JEX="$ROOT/target/debug/jex"
fi
CONFIG="${JEX_DAEMON_CONFIG:-$ROOT/examples/daemon.json}"
export JEX_NMH_NO_UI="${JEX_NMH_NO_UI:-1}"
LOG="${JEX_NMH_LOG:-$HOME/Library/Logs/jex-nmcades-host.log}"
mkdir -p "$(dirname "$LOG")"
echo "$(date '+%Y-%m-%dT%H:%M:%S') start jex=$JEX" >>"$LOG"
exec "$JEX" nmcades-host --config "$CONFIG" 2>>"$LOG"
