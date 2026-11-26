#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Replace CryptoPro system nmcades with jex (Safari / Firefox / system Chrome NMH).
# Safari hardcodes:
#   /Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades
# so the Chrome user-level NMH swap is not enough for Safari.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
JEX="${JEX:-$ROOT/target/release/jex}"
CONFIG="${JEX_DAEMON_CONFIG:-$ROOT/examples/daemon.json}"
NMCADES="/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades"
BACKUP="${NMCADES}.cryptopro.bak"

if [ ! -x "$JEX" ]; then
  echo "error: jex not found at $JEX (cargo build --release)" >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "error: config not found at $CONFIG" >&2
  exit 1
fi
if [ ! -e "$NMCADES" ]; then
  echo "error: CryptoPro nmcades not found at $NMCADES" >&2
  exit 1
fi

JEX_ABS="$(CDPATH= cd -- "$(dirname "$JEX")" && pwd)/$(basename "$JEX")"
CONFIG_ABS="$(CDPATH= cd -- "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"

WRAPPER="$(mktemp)"
trap 'rm -f "$WRAPPER"' EXIT
cat >"$WRAPPER" <<EOF
#!/bin/sh
# Installed by jex examples/install-system-nmcades.sh — drop-in for CryptoPro nmcades.
set -eu
JEX="\${JEX:-$JEX_ABS}"
CONFIG="\${JEX_DAEMON_CONFIG:-$CONFIG_ABS}"
# Browsers may pass an origin / unused argv; do not forward to clap.
exec "\$JEX" nmcades-host --config "\$CONFIG"
EOF
chmod 755 "$WRAPPER"

echo "Installing jex wrapper (admin password may be required)…"
# Prefer GUI elevation — works when terminal sudo has no tty password.
osascript <<APPLESCRIPT
do shell script "set -e
if [ ! -e '$BACKUP' ]; then cp -p '$NMCADES' '$BACKUP'; fi
cp '$WRAPPER' '$NMCADES'
chmod 755 '$NMCADES'
" with administrator privileges
APPLESCRIPT

echo "Done. Safari/Firefox/system NMH now use:"
echo "  $JEX_ABS"
echo "  --config $CONFIG_ABS"
echo "Backup: $BACKUP"
echo "Restore: $ROOT/examples/uninstall-system-nmcades.sh"
echo "Quit Safari (and Chrome) so they respawn nmcades."
