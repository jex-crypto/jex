#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
# Sync Safari UUID into ~/Library/Safari/NativeMessagingHosts/ru.jex.nmcades.json
# Ad-hoc / Debug appex UUID changes on every codesign — must refresh after Run.
set -eu
ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
HOST_SH="$ROOT/extension/host/jex-nmcades-host.sh"
EXT_ID="${JEX_EXTENSION_ID:-ogfkpliagdeofggffdpifnakdhgfiagc}"
OUT="$HOME/Library/Safari/NativeMessagingHosts/ru.jex.nmcades.json"
mkdir -p "$(dirname "$OUT")"

UUID="$(pluginkit -mAvvv -p com.apple.Safari.web-extension 2>/dev/null \
  | awk '/local\.jex\.Jex\.Extension/{p=1} p&&/UUID/{print $NF; exit}')"

python3 - "$HOST_SH" "$EXT_ID" "$OUT" "$UUID" <<'PY'
import json, sys
host, ext_id, out, uuid = sys.argv[1:5]
origins = [f"chrome-extension://{ext_id}/"]
# Keep any previous safari-web-extension origins (UUID churn) + current
prev = []
try:
    prev = json.load(open(out)).get("allowed_origins") or []
except Exception:
    pass
for o in prev:
    if o.startswith("safari-web-extension://") and o not in origins:
        origins.append(o)
if uuid:
    for u in (uuid, uuid.lower()):
        o = f"safari-web-extension://{u}/"
        if o not in origins:
            origins.append(o)
# Cap history so the list stays small
safari = [o for o in origins if o.startswith("safari-web-extension://")]
other = [o for o in origins if not o.startswith("safari-web-extension://")]
origins = other + safari[-6:]
obj = {
    "name": "ru.jex.nmcades",
    "description": "Jex Native Messaging Host",
    "path": host,
    "type": "stdio",
    "allowed_origins": origins,
}
open(out, "w").write(json.dumps(obj, indent=2) + "\n")
print("synced", out)
print("uuid=", uuid or "(none)")
print("origins=", origins)
PY
