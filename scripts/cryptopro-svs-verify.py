#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
"""Verify SignedXML / XAdES via CryptoPro SVS public REST API.

Unlike the web UI default (plain XMLDSig), this always sends UseXades=true so
SVS reports XadesType (BES / T / XLT1). XAdES-A support depends on the deployed
SVS/libxades build; use the reported XadesType rather than generic XMLDSig success.

Usage
-----
    python3 scripts/cryptopro-svs-verify.py testdata/xmldsig/jex_xades_a.xml
    python3 scripts/cryptopro-svs-verify.py --report-out /tmp/svs.pdf FILE.xml
    python3 scripts/cryptopro-svs-verify.py --no-xades FILE.xml   # match web UI

env:
    JEX_SVS_URL  base (default https://dss.cryptopro.ru/verify/rest/api)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_BASE = "https://dss.cryptopro.ru/verify/rest/api"
SIGNATURE_TYPE_XMLDSIG = 0


def http_json(url: str, body: Dict[str, Any], timeout: float = 90.0) -> Any:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", "replace")
        raise SystemExit(f"SVS HTTP {e.code}: {err[:2000]}") from e


def http_multipart_package(
    url: str,
    xml_path: Path,
    xml_bytes: bytes,
    verify_params: Dict[str, str],
    timeout: float = 120.0,
) -> Any:
    """POST /signatures/package as multipart (document + requestparam).

    VerifyParams is Dictionary<enum,string> on the server — all values must be
    strings (``\"true\"`` / ``\"PDF\"``), not JSON booleans.
    """
    boundary = "----jexSvsBoundary7MA4YWxkTrZu0gW"
    filename = xml_path.name
    requestparam = json.dumps(
        {
            "SignatureType": "XMLDSig",
            "VerifyParams": verify_params,
        },
        ensure_ascii=False,
    )

    parts: List[bytes] = []
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="document"; filename="{filename}"\r\n'
            f"Content-Type: application/xml\r\n\r\n"
        ).encode("utf-8")
        + xml_bytes
        + b"\r\n"
    )
    parts.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="requestparam"\r\n\r\n'
            f"{requestparam}\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
    )
    body = b"".join(parts)
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
        },
        method="POST",
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", "replace")
        raise SystemExit(f"SVS package HTTP {e.code}: {err[:2000]}") from e


def summarize_signer(item: Dict[str, Any]) -> None:
    si = item.get("SignatureInfo") or {}
    print(f"  Result:              {item.get('Result')}")
    print(f"  Message:             {item.get('Message')!r}")
    print(f"  XadesType:           {si.get('XadesType')}")
    print(f"  CAdESType:           {si.get('CAdESType')}")
    print(f"  SigningTime:         {si.get('SigningTime')}")
    print(f"  ArchiveSigningTime:  {si.get('ArchiveSigningTime')}")
    print(f"  Algorithm:           {si.get('AlgorithmName')} ({si.get('AlgorithmIdentifier')})")
    cert = item.get("SignerCertificateInfo") or {}
    if cert.get("SubjectName"):
        print(f"  Subject:             {cert.get('SubjectName')}")
        print(f"  Thumbprint:          {cert.get('Thumbprint')}")


def verify_single(
    path: Path,
    *,
    base: str,
    use_xades: bool,
    verify_as: Optional[str],
) -> List[Dict[str, Any]]:
    content = path.read_bytes()
    params: Dict[str, Any] = {"UseXades": use_xades}
    if verify_as:
        params["VerifyAs"] = verify_as
    body = {
        "SignatureType": SIGNATURE_TYPE_XMLDSIG,
        "Content": base64.b64encode(content).decode("ascii"),
        "VerifyParams": params,
    }
    result = http_json(f"{base.rstrip('/')}/signatures", body)
    if not isinstance(result, list):
        raise SystemExit(f"unexpected SVS response: {type(result)}")
    return result


def verify_package_report(
    path: Path,
    *,
    base: str,
    use_xades: bool,
    report_out: Path,
) -> None:
    params: Dict[str, str] = {
        "UseXades": "true" if use_xades else "false",
        "VerifyAll": "true",
        "VerifyReport": "true",
    }
    # ReportFormat is documented on some SVS builds but rejected by
    # dss.cryptopro.ru/verify (enum key conversion error) — omit it; default PDF.
    pkg = http_multipart_package(
        f"{base.rstrip('/')}/signatures/package",
        path,
        path.read_bytes(),
        params,
    )
    if not isinstance(pkg, dict):
        raise SystemExit(f"unexpected package response: {type(pkg)}")

    results = pkg.get("Results") or []
    print(f"Package documents: {len(results)}")
    for i, doc in enumerate(results):
        print(
            f"-- document[{i}] {doc.get('SignedDocumentName')} "
            f"SignatureType={doc.get('SignatureType')}"
        )
        for j, item in enumerate(doc.get("VerificationResults") or []):
            print(f"   signer[{j}]")
            summarize_signer(item)

    b64 = pkg.get("ResultsReportBase64")
    if not b64:
        print("WARN: no ResultsReportBase64 in package response", file=sys.stderr)
        return
    report_out.write_bytes(base64.b64decode(b64))
    print(f"Wrote PDF report: {report_out}")


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xml", type=Path, help="enveloped SignedXML / XAdES file")
    p.add_argument(
        "--base",
        default=os.environ.get("JEX_SVS_URL", DEFAULT_BASE),
        help="SVS REST API base URL",
    )
    p.add_argument(
        "--no-xades",
        action="store_true",
        help="omit UseXades (web-UI style → XMLDSig label)",
    )
    p.add_argument(
        "--verify-as",
        default=None,
        metavar="TYPE",
        help="optional VerifyAs: BES|T|XLT1|A",
    )
    p.add_argument(
        "--report-out",
        type=Path,
        default=None,
        metavar="PDF",
        help="also request package PDF protocol via /signatures/package",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    if not args.xml.is_file():
        print(f"FAIL: not found: {args.xml}", file=sys.stderr)
        return 1

    use_xades = not args.no_xades
    print(f"File: {args.xml} ({args.xml.stat().st_size} bytes)")
    print(f"SVS:  {args.base}")
    print(f"UseXades: {use_xades}")

    items = verify_single(
        args.xml,
        base=args.base,
        use_xades=use_xades,
        verify_as=args.verify_as,
    )
    print(f"Signers: {len(items)}")
    ok_all = True
    xades_type = None
    for i, item in enumerate(items):
        print(f"-- signer[{i}]")
        summarize_signer(item)
        if args.verbose:
            print(json.dumps(item.get("SignatureInfo") or {}, ensure_ascii=False, indent=2))
        if not item.get("Result"):
            ok_all = False
        si = item.get("SignatureInfo") or {}
        xades_type = si.get("XadesType") or xades_type

    if args.report_out is not None:
        verify_package_report(
            args.xml,
            base=args.base,
            use_xades=use_xades,
            report_out=args.report_out,
        )

    print("--- summary ---")
    print(json.dumps({
        "ok": ok_all,
        "use_xades": use_xades,
        "xades_type": xades_type,
        "path": str(args.xml),
    }, ensure_ascii=False))

    if use_xades and xades_type is None:
        print(
            "NOTE: no XadesType — XAdES path failed or UseXades ignored; "
            "math-only XMLDSig fallback is common when ATS is xades141.",
            file=sys.stderr,
        )
    if use_xades and xades_type == "XLT1":
        print(
            "NOTE: CryptoPro SVS qualifies this XML as XAdES-XLT1. "
            "XadesType=A for XML ArchiveTimeStamp is not observed on public SVS "
            "(CAdES-A works separately).",
            file=sys.stderr,
        )
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
