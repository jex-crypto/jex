#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
"""Throughput bench: parallel signatures against jex daemon.

Default: 100_000 raw GOST signatures on 8 client threads via POST /nmcades/raw-sign.

Example:
  cargo build --release
  JEX_DAEMON_WORKERS=8 ./target/release/jex daemon --config examples/daemon.json &
  ./scripts/bench-sign.py
  ./scripts/bench-sign.py --mode cms --count 1000   # slower CAdES-BES
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def post_json(url: str, token: str, body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def one_raw(url: str, token: str, key_id: str, hash_hex: str, timeout: float) -> None:
    out = post_json(
        url,
        token,
        {"key_id": key_id, "hash_hex": hash_hex},
        timeout,
    )
    if "signature_b64" not in out and "signature_hex" not in out:
        raise RuntimeError(f"unexpected response: {out!r}")


def one_cms(url: str, token: str, key_id: str, content_b64: str, timeout: float) -> None:
    out = post_json(
        url,
        token,
        {
            "key_id": key_id,
            "content_b64": content_b64,
            "detached": True,
            "cades_type": 1,  # BES
        },
        timeout,
    )
    if "signature_b64" not in out and "cms_b64" not in out:
        # accept common shapes
        if not any(k for k in out if "sign" in k.lower() or "cms" in k.lower()):
            raise RuntimeError(f"unexpected response: {out!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default=os.environ.get("JEX_DAEMON", "http://127.0.0.1:8787"))
    ap.add_argument("--token", default=os.environ.get("JEX_TOKEN", "dev-token-change-me"))
    ap.add_argument("--key-id", default="roman")
    ap.add_argument("--count", type=int, default=100_000)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--mode", choices=("raw", "cms"), default="raw")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument(
        "--hash-hex",
        default="00" * 32,
        help="32-byte digest hex for raw mode (Streebog-256 width)",
    )
    args = ap.parse_args()

    if args.mode == "raw":
        path = "/nmcades/raw-sign"
        # warmup / connectivity
        url = args.base.rstrip("/") + path

        def job(_i: int) -> None:
            one_raw(url, args.token, args.key_id, args.hash_hex, args.timeout)

    else:
        path = "/nmcades/sign"
        url = args.base.rstrip("/") + path
        content_b64 = base64.b64encode(b"jex-bench").decode()

        def job(_i: int) -> None:
            one_cms(url, args.token, args.key_id, content_b64, args.timeout)

    print(
        f"bench mode={args.mode} url={url} count={args.count} threads={args.threads}",
        flush=True,
    )
    try:
        job(-1)
    except urllib.error.URLError as e:
        print(f"daemon unreachable: {e}", file=sys.stderr)
        print(
            "start: JEX_DAEMON_WORKERS=8 ./target/release/jex daemon --config examples/daemon.json",
            file=sys.stderr,
        )
        return 2
    except Exception as e:
        print(f"warmup failed: {e}", file=sys.stderr)
        return 2
    print("warmup ok", flush=True)

    errors = 0
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = [pool.submit(job, i) for i in range(args.count)]
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                fut.result()
            except Exception as e:
                errors += 1
                if errors <= 5:
                    print(f"error: {e}", file=sys.stderr)
            if i % 10000 == 0 or i == args.count:
                elapsed = time.perf_counter() - t0
                rate = i / elapsed if elapsed > 0 else 0
                print(f"  {i}/{args.count}  {elapsed:.2f}s  {rate:.0f} sig/s", flush=True)
    elapsed = time.perf_counter() - t0
    ok = args.count - errors
    rate = ok / elapsed if elapsed > 0 else 0
    print(
        json.dumps(
            {
                "mode": args.mode,
                "count": args.count,
                "ok": ok,
                "errors": errors,
                "threads": args.threads,
                "seconds": round(elapsed, 3),
                "sigs_per_sec": round(rate, 1),
                "latency_ms_avg": round(1000.0 * elapsed / max(ok, 1), 3),
            },
            indent=2,
        )
    )
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
