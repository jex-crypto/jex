#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Restore CryptoPro system nmcades from backup.
set -eu

NMCADES="/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades"
BACKUP="${NMCADES}.cryptopro.bak"

if [ ! -e "$BACKUP" ]; then
  echo "error: backup not found at $BACKUP" >&2
  exit 1
fi

echo "Restoring original CryptoPro nmcades (admin password may be required)…"
osascript <<APPLESCRIPT
do shell script "cp -p '$BACKUP' '$NMCADES' && chmod 755 '$NMCADES'" with administrator privileges
APPLESCRIPT
echo "Done. Quit Safari/Chrome so they respawn the original nmcades."
