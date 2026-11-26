#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Reverse-interop: verify SignedXML / XAdES with CryptoPro nmcades (CADESCOM).
#
# cryptcp does not verify XML; this uses scripts/nmcades_xml_golden.py --verify-file.
#
# usage:
#   scripts/cryptopro-xml-verify.sh SIGNED.xml [SIGNED2.xml ...]
#
# env:
#   NMCADES  path to nmcades binary (default: CryptoPro ECP app on macOS)

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 SIGNED.xml [SIGNED.xml ...]" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NMCADES="${NMCADES:-/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades}"
export NMCADES

fail=0
for f in "$@"; do
  echo "== CryptoPro Verify: $f =="
  if ! python3 "$ROOT/scripts/nmcades_xml_golden.py" --nmcades "$NMCADES" --verify-file "$f"; then
    fail=1
  fi
done
exit "$fail"
