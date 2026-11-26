#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 CONTENT XLT1_SIGNATURE CADES_A_SIGNATURE" >&2
  exit 2
fi

CRYPTCP="${CRYPTCP:-/opt/cprocsp/bin/cryptcp}"
CONTENT="$1"
XLT1="$2"
CADESA="$3"

"$CRYPTCP" -verify -detached -xlongtype1 "$CONTENT" "$XLT1"
"$CRYPTCP" -verify -detached -cadesa "$CONTENT" "$CADESA"
