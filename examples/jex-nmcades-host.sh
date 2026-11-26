#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Chrome Native Messaging wrapper.
# Chrome passes the extension origin as argv[1]; jex does not need it.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
JEX="${JEX:-$ROOT/target/release/jex}"
if [ ! -x "$JEX" ]; then
  JEX="$ROOT/target/debug/jex"
fi
CONFIG="${JEX_DAEMON_CONFIG:-$ROOT/examples/daemon.json}"
# Do NOT forward Chrome's origin argv — clap would treat it as an error.
exec "$JEX" nmcades-host --config "$CONFIG"
