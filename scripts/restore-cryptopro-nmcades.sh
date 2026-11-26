#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
set -eu
NMCADES="/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades"
BACKUP="${NMCADES}.cryptopro.bak"
if [ ! -e "$BACKUP" ]; then
  echo "no backup at $BACKUP" >&2
  exit 1
fi
osascript <<APPLESCRIPT
do shell script "cp -p '$BACKUP' '$NMCADES' && chmod 755 '$NMCADES'" with administrator privileges
APPLESCRIPT
echo "restored CryptoPro nmcades"
