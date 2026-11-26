#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Roman Yerin
"""Golden SignedXML fixtures via CryptoPro native messaging host (nmcades).

Talks to the Chrome Native Messaging Host binary shipped with CryptoPro ECP
(`/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades`) using the same
4-byte LE length-prefixed JSON protocol as the CryptoPro Chrome extension
(`chrome-extension://pfhgbfnnjiafkhfdkmpiflachepdcjod/`).

Purpose
-------
Produce reference XMLDSIG / XAdES fixtures under `testdata/xmldsig/` for
interoperability checks (enveloped, enveloping, template, XAdES-BES/T/XLT1/A).
This is a **golden/reference harness only** — do not wire nmcades into the
Rust Jex product.

Protocol sketch (from extension content.js / nmcades_plugin_api.js)
-------------------------------------------------------------------
Spawn::

    nmcades chrome-extension://pfhgbfnnjiafkhfdkmpiflachepdcjod/

Each message: ``uint32_le(len) || utf8(json)``.

Envelope: ``{"tabid": "<uuid>", "data": { ... }}``.

Init::

    data = {"destination": "nmcades", "requestid": N, "type": "init",
            "url": "https://localhost/"}

CreateObject / method / property (async plugin shapes)::

    {"objid": ID, "method": "CreateObject",
     "params": [{"type": "string", "value": "CAdESCOM.About"}], ...}
    {"objid": ID, "get_property": "Version", ...}
    {"objid": ID, "set_property": "Content",
     "params": [{"type": "string", "value": "..."}], ...}

Host may send ``data.type == "callback"``. Reply by flipping type to
``"result"`` and attaching ``params`` (content.js pattern)::

    value "result = window.document.URL"
      → params [{"type":"string","value":"https://localhost/"}]
    value "result = cadesplugin.EnableInternalCSP"
      → params [{"type":"boolean","value":false}]
    type "approved_site"
      → params [{"type":"boolean","value":true}]   # treat as approved for harness

Usage
-----
Smoke (About + SignedXML CreateObject)::

    python3 scripts/nmcades_xml_golden.py

Sign all packaging modes + XAdES-BES/T/XLT1/A::

    python3 scripts/nmcades_xml_golden.py --all --cert-subject ИВАНОВ
    CRYPTOPRO_PIN=**** python3 scripts/nmcades_xml_golden.py --all --pin-file /path/to.pin

Or selectively::

    python3 scripts/nmcades_xml_golden.py --sign --enveloping --template --xades-bes
    python3 scripts/nmcades_xml_golden.py --xades-t --xades-xlt1 --cert-subject ИВАНОВ
    # Note: CADESCOM SignedXML.Sign with 0x7d0 may return 0x80070057 on some builds;
    # prefer jex `xml archive` + --verify-file for XAdES-A reverse checks.

Reverse verify (jex-signed or any SignedXML file)::

    python3 scripts/nmcades_xml_golden.py --verify-file testdata/xmldsig/jex_enveloped_synthetic.xml

Outputs (under testdata/xmldsig/, with ``--sign`` / ``--all``)::

    input_enveloped.xml
    input_template.xml
    nmcades_enveloped.xml (+ .meta.json)
    nmcades_enveloping.xml (+ .meta.json)
    nmcades_template.xml (+ .meta.json)     # if template Sign succeeds
    nmcades_xades_bes.xml (+ .meta.json)    # SignatureType = ENVELOPED|0x20
    nmcades_xades_t.xml (+ .meta.json)      # ENVELOPED|0x50 + TSA
    nmcades_xades_xlt1.xml (+ .meta.json)   # ENVELOPED|0x5d0 + TSA
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import struct
import subprocess
import sys
import threading
import traceback
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_NMCADES = "/Applications/CryptoPro_ECP.app/Contents/MacOS/bin/nmcades"
EXTENSION_ORIGIN = "chrome-extension://pfhgbfnnjiafkhfdkmpiflachepdcjod/"
DEFAULT_DOC_URL = "https://localhost/"

CAPICOM_CURRENT_USER_STORE = 2
CAPICOM_MY_STORE = "My"
CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2

CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0
CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1
CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2
CADESCOM_XADES_BES = 0x00000020
CADESCOM_XADES_T = 0x00000050
CADESCOM_XADES_X_LONG_TYPE_1 = 0x000005D0
# Official CADESCOM / xades.h value (not CAdES 0xdd / mistaken 0xdd0).
CADESCOM_XADES_A = 0x000007D0
# CryptoPro: packaging (low 2 bits) OR-ed with XAdES flags.
CADESCOM_ENVELOPED_XADES_BES = CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED | CADESCOM_XADES_BES
CADESCOM_ENVELOPED_XADES_T = CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED | CADESCOM_XADES_T
CADESCOM_ENVELOPED_XADES_XLT1 = (
    CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED | CADESCOM_XADES_X_LONG_TYPE_1
)
CADESCOM_ENVELOPED_XADES_A = (
    CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED | CADESCOM_XADES_A
)

DEFAULT_TSA_URL = "http://qs.cryptopro.ru/tsp/tsp.srf"
# XAdES-T needs TSA round-trip; XLT1 also fetches OCSP/CRL — allow more time.
SIGN_TIMEOUT_DEFAULT = 120.0
SIGN_TIMEOUT_XADES_T = 180.0
SIGN_TIMEOUT_XADES_XLT1 = 420.0
SIGN_TIMEOUT_XADES_A = 480.0
VERIFY_TIMEOUT_DEFAULT = 60.0
VERIFY_TIMEOUT_XADES = 180.0

XMLDSIG_GOST3410_2012_256 = (
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256"
)
XMLDSIG_GOST3411_2012_256 = (
    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"
)
EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
ENVELOPED_TRANSFORM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"

MINIMAL_XML = '<?xml version="1.0"?><Document><Body>golden</Body></Document>\n'

# Template adapted from CryptoPro plugin-samples-sign-xml-template (empty DigestValue /
# SignatureValue / KeyInfo; Reference URI="" + enveloped + Exc-C14N).
TEMPLATE_XML = f"""\
<?xml version="1.0"?>
<Document>
  <Body>golden</Body>
  <Signature xmlns="{XMLDSIG_NS}">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="{EXC_C14N}"/>
      <SignatureMethod Algorithm="{XMLDSIG_GOST3410_2012_256}"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="{ENVELOPED_TRANSFORM}"/>
          <Transform Algorithm="{EXC_C14N}"/>
        </Transforms>
        <DigestMethod Algorithm="{XMLDSIG_GOST3411_2012_256}"/>
        <DigestValue/>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo/>
  </Signature>
</Document>
"""

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "testdata" / "xmldsig"


class NmcadesError(RuntimeError):
    """Host returned type=error or a transport failure."""


class NmcadesSession:
    """Native-messaging session with automatic callback replies."""

    def __init__(
        self,
        nmcades_path: str,
        extension_origin: str = EXTENSION_ORIGIN,
        doc_url: str = DEFAULT_DOC_URL,
        tabid: Optional[str] = None,
        default_timeout: float = 30.0,
        verbose: bool = False,
    ) -> None:
        self.doc_url = doc_url
        self.tabid = tabid or str(uuid.uuid4())
        self.default_timeout = default_timeout
        self.verbose = verbose
        self._request_id = 0
        self._pending: Dict[int, queue.Queue] = {}
        self._lock = threading.Lock()
        self._partial: Dict[str, str] = {}
        self._alive = True
        self._plugin_objid: Optional[int] = None

        if not os.path.isfile(nmcades_path):
            raise FileNotFoundError(f"nmcades binary not found: {nmcades_path}")

        self._proc = subprocess.Popen(
            [nmcades_path, extension_origin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        assert self._proc.stdin is not None and self._proc.stdout is not None

        self._reader = threading.Thread(target=self._read_loop, name="nmcades-reader", daemon=True)
        self._reader.start()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, name="nmcades-stderr", daemon=True
        )
        self._stderr_thread.start()

    # -- transport ----------------------------------------------------------

    def _log(self, *args: Any) -> None:
        if self.verbose:
            print("[nmcades]", *args, file=sys.stderr)

    def _drain_stderr(self) -> None:
        assert self._proc.stderr is not None
        for line in iter(self._proc.stderr.readline, b""):
            try:
                text = line.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            if text:
                self._log("stderr:", text)

    def _send_raw(self, envelope: Dict[str, Any]) -> None:
        payload = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        header = struct.pack("<I", len(payload))
        self._log(">>", envelope)
        try:
            self._proc.stdin.write(header + payload)
            self._proc.stdin.flush()
        except BrokenPipeError as exc:
            raise NmcadesError("nmcades stdin closed (host exited)") from exc

    def _read_exact(self, n: int) -> bytes:
        assert self._proc.stdout is not None
        buf = b""
        while len(buf) < n:
            chunk = self._proc.stdout.read(n - len(buf))
            if not chunk:
                raise EOFError("nmcades stdout closed")
            buf += chunk
        return buf

    def _deliver(self, requestid: int, message: Dict[str, Any]) -> None:
        with self._lock:
            q = self._pending.get(requestid)
        if q is None:
            self._log("orphan reply for requestid", requestid, message)
            return
        q.put(message)

    def _handle_callback(self, envelope: Dict[str, Any]) -> None:
        """Mirror content.js / background.js callback replies."""
        data = envelope.get("data") or {}
        value = data.get("value")
        reply = dict(envelope)
        reply_data = dict(data)
        reply_data["type"] = "result"

        if value == "result = window.document.URL":
            reply_data["params"] = [{"type": "string", "value": self.doc_url}]
        elif value == "result = cadesplugin.EnableInternalCSP":
            reply_data["params"] = [{"type": "boolean", "value": False}]
        elif data.get("type") == "approved_site" or (
            isinstance(value, str)
            and (
                value.startswith("add_approved_site:")
                or value.startswith("is_approved_site:")
            )
        ):
            # Harness has no UI; approve so Store/Sign can proceed when possible.
            reply_data["params"] = [{"type": "boolean", "value": True}]
        elif data.get("object") is not None:
            # Certificate-picker callback — cannot satisfy without UI.
            self._log("callback with object (cert UI?) — ignoring:", data)
            return
        else:
            self._log("unknown callback, answering with empty string:", data)
            reply_data["params"] = [
                {"type": "string", "value": "Internal error on harness callback"}
            ]

        reply["data"] = reply_data
        self._log("callback reply:", reply)
        self._send_raw(reply)

    def _dispatch_message(self, message: Dict[str, Any]) -> None:
        if message.get("error"):
            self._log("fatal host error:", message["error"])
            return

        # Partial message reassembly (background.js).
        if "partial" in message:
            key = f"{message.get('tabid')}:{message.get('requestid')}"
            part = message.get("part", "")
            partial = message["partial"]
            if partial == 1:
                self._partial[key] = part
                return
            if partial > 1:
                self._partial[key] = self._partial.get(key, "") + part
                return
            if partial == -1:
                blob = self._partial.pop(key, "") + part
                try:
                    message = json.loads(blob)
                except json.JSONDecodeError as exc:
                    self._log("failed to parse partial message:", exc)
                    return
            else:
                return

        data = message.get("data") or {}
        dtype = data.get("type")

        if dtype == "callback" or dtype == "approved_site":
            # approved_site is handled like a callback with boolean params.
            if dtype == "approved_site":
                # Ensure _handle_callback sees the type.
                data = dict(data)
                message = dict(message)
                message["data"] = data
            self._handle_callback(message)
            return

        requestid = data.get("requestid")
        if requestid is None:
            self._log("message without requestid:", message)
            return
        self._deliver(int(requestid), message)

    def _read_loop(self) -> None:
        try:
            while self._alive:
                try:
                    header = self._read_exact(4)
                except EOFError:
                    break
                (length,) = struct.unpack("<I", header)
                if length > 64 * 1024 * 1024:
                    # CP_PRINT_CHAIN_DETAIL writes human-readable diagnostics
                    # to the native host's stdout, interleaved with framed
                    # JSON. Slide until the next plausible frame whose payload
                    # starts with a JSON object, preserving the diagnostics.
                    noise = bytearray()
                    window = bytearray(header)
                    while True:
                        noise.append(window[0])
                        window = window[1:] + self._read_exact(1)
                        (length,) = struct.unpack("<I", window)
                        if 0 < length <= 64 * 1024 * 1024:
                            first = self._read_exact(1)
                            if first == b"{":
                                body = first + self._read_exact(length - 1)
                                break
                            window = bytearray(window[1:] + first)
                    self._log(
                        "unframed stdout:",
                        noise.decode("utf-8", errors="replace").rstrip(),
                    )
                else:
                    body = self._read_exact(length)
                try:
                    message = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError as exc:
                    self._log("bad JSON from host:", exc, body[:200])
                    continue
                self._log("<<", message)
                try:
                    self._dispatch_message(message)
                except Exception:
                    self._log("dispatch error:\n", traceback.format_exc())
        finally:
            self._alive = False
            # Unblock waiters.
            with self._lock:
                for q in self._pending.values():
                    q.put({"data": {"type": "error", "message": "nmcades reader stopped"}})

    # -- high-level RPC -----------------------------------------------------

    def _next_request_id(self) -> int:
        with self._lock:
            self._request_id += 1
            return self._request_id

    def call(self, data: Dict[str, Any], timeout: Optional[float] = None) -> Dict[str, Any]:
        requestid = int(data.setdefault("requestid", self._next_request_id()))
        data.setdefault("destination", "nmcades")
        q: queue.Queue = queue.Queue(maxsize=1)
        with self._lock:
            self._pending[requestid] = q
        try:
            self._send_raw({"tabid": self.tabid, "data": data})
            try:
                message = q.get(timeout=timeout if timeout is not None else self.default_timeout)
            except queue.Empty as exc:
                raise TimeoutError(
                    f"timeout waiting for requestid={requestid} data={data!r}"
                ) from exc
        finally:
            with self._lock:
                self._pending.pop(requestid, None)

        reply = message.get("data") or {}
        if reply.get("type") == "error":
            raise NmcadesError(reply.get("message") or json.dumps(reply, ensure_ascii=False))
        return reply

    def init(self, url: Optional[str] = None) -> int:
        reply = self.call({"type": "init", "url": url or self.doc_url})
        # Init returns plugin root objid in data.value (nmcades_plugin_api.js).
        value = reply.get("value")
        if value is None and isinstance(reply.get("retval"), dict):
            value = reply["retval"].get("value")
        if value is None:
            raise NmcadesError(f"init failed: unexpected reply {reply!r}")
        self._plugin_objid = int(value)
        return self._plugin_objid

    @staticmethod
    def _encode_param(value: Any) -> Dict[str, Any]:
        if isinstance(value, bool):
            return {"type": "boolean", "value": value}
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return {"type": "number", "value": value}
        if isinstance(value, dict) and "objid" in value:
            return {"type": "object", "value": value["objid"]}
        if isinstance(value, NmcadesObject):
            return {"type": "object", "value": value.objid}
        return {"type": "string", "value": str(value)}

    def create_object(self, prog_id: str, timeout: Optional[float] = None) -> "NmcadesObject":
        if self._plugin_objid is None:
            raise NmcadesError("call init() first")
        reply = self.call(
            {
                "objid": self._plugin_objid,
                "method": "CreateObject",
                "params": [{"type": "string", "value": prog_id}],
            },
            timeout=timeout,
        )
        return self._object_from_retval(reply)

    def _object_from_retval(self, reply: Dict[str, Any]) -> "NmcadesObject":
        retval = reply.get("retval")
        if not isinstance(retval, dict):
            if "value" in reply:
                retval = reply
            else:
                raise NmcadesError(f"expected object retval, got {reply!r}")
        rtype = retval.get("type")
        if rtype not in (None, "object"):
            if "properties" not in retval and "methods" not in retval:
                raise NmcadesError(f"CreateObject returned non-object: {reply!r}")
        objid = int(retval["value"])
        props = list(retval.get("properties") or [])
        methods = list(retval.get("methods") or [])
        return NmcadesObject(self, objid, props, methods)

    def get_property(self, objid: int, name: str, timeout: Optional[float] = None) -> Any:
        reply = self.call({"objid": objid, "get_property": name}, timeout=timeout)
        return self._decode_retval(reply)

    def set_property(
        self, objid: int, name: str, value: Any, timeout: Optional[float] = None
    ) -> Any:
        reply = self.call(
            {
                "objid": objid,
                "set_property": name,
                "params": [self._encode_param(value)],
            },
            timeout=timeout,
        )
        return self._decode_retval(reply)

    def invoke(
        self, objid: int, method: str, *args: Any, timeout: Optional[float] = None
    ) -> Any:
        reply = self.call(
            {
                "objid": objid,
                "method": method,
                "params": [self._encode_param(a) for a in args],
            },
            timeout=timeout,
        )
        return self._decode_retval(reply)

    def _decode_retval(self, reply: Dict[str, Any]) -> Any:
        retval = reply.get("retval", reply)
        if not isinstance(retval, dict):
            return retval
        rtype = retval.get("type")
        if rtype == "object" or (
            "properties" in retval or "methods" in retval
        ) and "value" in retval:
            return self._object_from_retval({"retval": retval})
        if rtype == "string":
            return retval.get("value")
        if rtype == "number":
            v = retval.get("value")
            try:
                return int(v)
            except (TypeError, ValueError):
                return float(v)
        if rtype == "boolean":
            return bool(retval.get("value"))
        if rtype == "OK":
            return None
        # Fallback: bare value from init-like replies
        if "value" in retval and rtype is None:
            return retval["value"]
        return retval

    def close(self) -> None:
        self._alive = False
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=3)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


class NmcadesObject:
    def __init__(
        self,
        session: NmcadesSession,
        objid: int,
        properties: List[str],
        methods: List[str],
    ) -> None:
        self._session = session
        self.objid = objid
        self.properties = properties
        self.methods = methods

    def get(self, name: str, timeout: Optional[float] = None) -> Any:
        return self._session.get_property(self.objid, name, timeout=timeout)

    def set(self, name: str, value: Any, timeout: Optional[float] = None) -> Any:
        return self._session.set_property(self.objid, name, value, timeout=timeout)

    def call(self, method: str, *args: Any, timeout: Optional[float] = None) -> Any:
        return self._session.invoke(self.objid, method, *args, timeout=timeout)

    def __repr__(self) -> str:
        return (
            f"NmcadesObject(objid={self.objid}, "
            f"props={self.properties!r}, methods={self.methods!r})"
        )


def _stringify_version(about: NmcadesObject) -> str:
    """Best-effort About version string."""
    for prop in ("Version", "PluginVersion"):
        if prop not in about.properties and about.properties:
            # Still try — host may omit property lists on some builds.
            pass
        try:
            v = about.get(prop, timeout=10)
        except Exception:
            continue
        if isinstance(v, str) and v:
            return v
        if isinstance(v, NmcadesObject):
            # Version object: try toString method or Major/Minor/Build.
            if "toString" in v.methods:
                try:
                    s = v.call("toString", timeout=10)
                    if s:
                        return str(s)
                except Exception:
                    pass
            parts = []
            for p in ("MajorVersion", "MinorVersion", "BuildVersion"):
                try:
                    parts.append(str(v.get(p, timeout=5)))
                except Exception:
                    parts.append("?")
            if parts:
                return ".".join(parts)
    return "<unknown>"


def list_certificates(store: NmcadesObject, timeout: float = 60.0) -> List[Dict[str, Any]]:
    certs_col = store.get("Certificates", timeout=timeout)
    if not isinstance(certs_col, NmcadesObject):
        raise NmcadesError(f"Store.Certificates is not an object: {certs_col!r}")
    count = int(certs_col.get("Count", timeout=timeout))
    out: List[Dict[str, Any]] = []
    for i in range(1, count + 1):
        cert = certs_col.call("Item", i, timeout=timeout)
        if not isinstance(cert, NmcadesObject):
            continue
        info: Dict[str, Any] = {"obj": cert, "index": i}
        for prop in ("SubjectName", "Thumbprint", "SerialNumber", "IssuerName"):
            try:
                info[prop] = cert.get(prop, timeout=10)
            except Exception as exc:
                info[prop] = f"<error: {exc}>"
        out.append(info)
    return out


def make_signer(
    session: NmcadesSession,
    cert: NmcadesObject,
    pin: Optional[str],
    tsa_url: Optional[str] = None,
) -> Tuple[NmcadesObject, Optional[str]]:
    """Create CPSigner; optionally set TSA URL.

    Returns ``(signer, tsa_property_used)`` where ``tsa_property_used`` is the
    property name that accepted the URL (``TSAAddress`` or ``TSPAddress``), or
    ``None`` if no TSA was requested / both failed.
    """
    signer = session.create_object("CAdESCOM.CPSigner", timeout=30)
    print(f"    CPSigner props={signer.properties} methods={signer.methods}")
    signer.set("Certificate", cert)
    if pin:
        try:
            signer.set("KeyPin", pin)
        except Exception as exc:
            print(f"WARN: propset KeyPin failed: {exc}", file=sys.stderr)
    try:
        signer.set("CheckCertificate", False)
    except Exception:
        pass

    tsa_prop_used: Optional[str] = None
    if tsa_url:
        # Official CADESCOM name is TSAAddress; some builds expose TSPAddress.
        for prop in ("TSAAddress", "TSPAddress"):
            if signer.properties and prop not in signer.properties:
                # Property list present but name absent — still try (lists can be incomplete).
                pass
            try:
                signer.set(prop, tsa_url, timeout=15)
                tsa_prop_used = prop
                print(f"OK  CPSigner.{prop} = {tsa_url}")
                break
            except Exception as exc:
                print(f"WARN: propset {prop} failed: {exc}", file=sys.stderr)
        if tsa_prop_used is None:
            raise NmcadesError(
                f"could not set TSA URL on CPSigner (tried TSAAddress, TSPAddress): {tsa_url}"
            )
    return signer, tsa_prop_used


def sign_xml(
    session: NmcadesSession,
    cert: NmcadesObject,
    content: str,
    signature_type: int,
    pin: Optional[str],
    *,
    set_methods: bool = True,
    tsa_url: Optional[str] = None,
    sign_timeout: float = SIGN_TIMEOUT_DEFAULT,
) -> Tuple[str, Optional[str]]:
    """Sign content with CAdESCOM.SignedXML.

    ``signature_type`` is the CryptoPro combined flag
    (packaging | XAdES), e.g. 0 / 1 / 2 / (0|0x20) / (0|0x50) / (0|0x5d0).
    For TEMPLATE mode CryptoPro fills algorithms from the template itself;
    ``set_methods`` can be False in that case.

    Returns ``(signed_xml, tsa_property_used)``.
    """
    signer, tsa_prop = make_signer(session, cert, pin, tsa_url=tsa_url)
    signed_xml = session.create_object("CAdESCOM.SignedXML", timeout=30)
    signed_xml.set("Content", content)
    signed_xml.set("SignatureType", signature_type)
    if set_methods:
        signed_xml.set("SignatureMethod", XMLDSIG_GOST3410_2012_256)
        signed_xml.set("DigestMethod", XMLDSIG_GOST3411_2012_256)

    result = signed_xml.call("Sign", signer, timeout=sign_timeout)
    if not isinstance(result, str) or not result.strip():
        raise NmcadesError(f"Sign returned unexpected value: {result!r}")
    return result, tsa_prop


def verify_signed(
    session: NmcadesSession,
    signed: str,
    *,
    timeout: float = VERIFY_TIMEOUT_DEFAULT,
) -> None:
    """Verify signed XML via CAdESCOM.SignedXML.

    Sets ``Content`` then calls ``Verify`` with the signed document (CryptoPro
    plugin pattern). Falls back to ``Verify(signed)`` alone if Content set fails.
    """
    verifier = session.create_object("CAdESCOM.SignedXML", timeout=30)
    try:
        verifier.set("Content", signed, timeout=30)
    except Exception as exc:
        print(f"WARN: SignedXML.Content set failed ({exc}); Verify(arg) only", file=sys.stderr)
    verifier.call("Verify", signed, timeout=timeout)


def unsigned_signature_property_names(signed_xml: str) -> List[str]:
    """Local names of element children under UnsignedSignatureProperties."""
    try:
        root = ET.fromstring(signed_xml)
    except ET.ParseError as exc:
        return [f"<parse_error: {exc}>"]

    names: List[str] = []
    # Match by local name regardless of prefix/default xmlns.
    for el in root.iter():
        tag = el.tag
        local = tag.rsplit("}", 1)[-1] if isinstance(tag, str) else str(tag)
        if local != "UnsignedSignatureProperties":
            continue
        for child in list(el):
            ctag = child.tag
            clocal = ctag.rsplit("}", 1)[-1] if isinstance(ctag, str) else str(ctag)
            names.append(clocal)
    return names


def read_pin(args: argparse.Namespace) -> Optional[str]:
    if args.pin:
        return args.pin
    if args.pin_file:
        return Path(args.pin_file).read_text(encoding="utf-8").strip()
    env = os.environ.get("CRYPTOPRO_PIN")
    return env.strip() if env else None


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"Wrote {path}")


def select_cert(
    certs: List[Dict[str, Any]],
    thumbprint: Optional[str],
    subject: Optional[str],
) -> Optional[Dict[str, Any]]:
    if thumbprint:
        tp = thumbprint.replace(" ", "").upper()
        matched = [
            c
            for c in certs
            if str(c.get("Thumbprint", "")).replace(" ", "").upper() == tp
        ]
        if not matched:
            print(f"FAIL: no cert with thumbprint {thumbprint}")
            return None
        return matched[0]
    if subject:
        needle = subject.lower()
        matched = [
            c for c in certs if needle in str(c.get("SubjectName", "")).lower()
        ]
        if not matched:
            print(f"FAIL: no cert SubjectName containing {subject!r}")
            return None
        return matched[0]
    return certs[0]


def save_signed_fixture(
    out_dir: Path,
    stem: str,
    signed: str,
    meta: Dict[str, Any],
) -> None:
    path = out_dir / f"{stem}.xml"
    save_text(path, signed if signed.endswith("\n") else signed + "\n")
    meta_path = out_dir / f"{stem}.meta.json"
    save_text(meta_path, json.dumps(meta, ensure_ascii=False, indent=2) + "\n")


def run_sign_jobs(
    session: NmcadesSession,
    selected: Dict[str, Any],
    pin: Optional[str],
    out_dir: Path,
    about_version: Any,
    doc_url: str,
    jobs: List[str],
    status: Dict[str, Any],
    tsa_url: str,
    *,
    verbose: bool = False,
) -> None:
    """Run named sign jobs including XAdES-BES/T/XLT1."""
    base_meta = {
        "source": "nmcades",
        "signature_method": XMLDSIG_GOST3410_2012_256,
        "digest_method": XMLDSIG_GOST3411_2012_256,
        "subject": selected.get("SubjectName"),
        "thumbprint": selected.get("Thumbprint"),
        "about_version": about_version,
        "doc_url": doc_url,
    }
    cert = selected["obj"]

    job_specs: Dict[str, Dict[str, Any]] = {
        "enveloped": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED,
            "set_methods": True,
            "stem": "nmcades_enveloped",
            "tsa": False,
            "sign_timeout": SIGN_TIMEOUT_DEFAULT,
            "verify_timeout": VERIFY_TIMEOUT_DEFAULT,
            "meta_extra": {
                "signature_type": "enveloped",
                "signature_type_value": CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED,
                "xades_flags": 0,
                "input": "input_enveloped.xml",
            },
        },
        "enveloping": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING,
            "set_methods": True,
            "stem": "nmcades_enveloping",
            "tsa": False,
            "sign_timeout": SIGN_TIMEOUT_DEFAULT,
            "verify_timeout": VERIFY_TIMEOUT_DEFAULT,
            "meta_extra": {
                "signature_type": "enveloping",
                "signature_type_value": CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING,
                "xades_flags": 0,
                "input": "input_enveloped.xml",
            },
        },
        "template": {
            "content": TEMPLATE_XML,
            "sig_type": CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE,
            # Algorithms already in the template SignedInfo.
            "set_methods": False,
            "stem": "nmcades_template",
            "tsa": False,
            "sign_timeout": SIGN_TIMEOUT_DEFAULT,
            "verify_timeout": VERIFY_TIMEOUT_DEFAULT,
            "meta_extra": {
                "signature_type": "template",
                "signature_type_value": CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE,
                "xades_flags": 0,
                "input": "input_template.xml",
            },
        },
        "xades_bes": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_ENVELOPED_XADES_BES,
            "set_methods": True,
            "stem": "nmcades_xades_bes",
            "tsa": False,
            "sign_timeout": SIGN_TIMEOUT_DEFAULT,
            "verify_timeout": VERIFY_TIMEOUT_DEFAULT,
            "meta_extra": {
                "signature_type": "enveloped",
                "signature_type_value": CADESCOM_ENVELOPED_XADES_BES,
                "xades_flags": CADESCOM_XADES_BES,
                "xades_profile": "BES",
                "input": "input_enveloped.xml",
            },
        },
        "xades_t": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_ENVELOPED_XADES_T,
            "set_methods": True,
            "stem": "nmcades_xades_t",
            "tsa": True,
            "sign_timeout": SIGN_TIMEOUT_XADES_T,
            "verify_timeout": VERIFY_TIMEOUT_XADES,
            "meta_extra": {
                "signature_type": "enveloped",
                "signature_type_value": CADESCOM_ENVELOPED_XADES_T,
                "xades_flags": CADESCOM_XADES_T,
                "xades_profile": "T",
                "tsa_url": tsa_url,
                "input": "input_enveloped.xml",
            },
        },
        "xades_xlt1": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_ENVELOPED_XADES_XLT1,
            "set_methods": True,
            "stem": "nmcades_xades_xlt1",
            "tsa": True,
            "sign_timeout": SIGN_TIMEOUT_XADES_XLT1,
            "verify_timeout": VERIFY_TIMEOUT_XADES,
            "meta_extra": {
                "signature_type": "enveloped",
                "signature_type_value": CADESCOM_ENVELOPED_XADES_XLT1,
                "xades_flags": CADESCOM_XADES_X_LONG_TYPE_1,
                "xades_profile": "X_LONG_TYPE_1",
                "tsa_url": tsa_url,
                "input": "input_enveloped.xml",
            },
        },
        "xades_a": {
            "content": MINIMAL_XML,
            "sig_type": CADESCOM_ENVELOPED_XADES_A,
            "set_methods": True,
            "stem": "nmcades_xades_a",
            "tsa": True,
            "sign_timeout": SIGN_TIMEOUT_XADES_A,
            "verify_timeout": VERIFY_TIMEOUT_XADES,
            "meta_extra": {
                "signature_type": "enveloped",
                "signature_type_value": CADESCOM_ENVELOPED_XADES_A,
                "xades_flags": CADESCOM_XADES_A,
                "xades_profile": "A",
                "tsa_url": tsa_url,
                "input": "input_enveloped.xml",
            },
        },
    }

    for name in jobs:
        spec = job_specs[name]
        print(
            f"Sign [{name}] SignatureType={spec['sig_type']} "
            f"(0x{spec['sig_type']:x}) timeout={spec['sign_timeout']}s…"
        )
        try:
            signed, tsa_prop = sign_xml(
                session,
                cert,
                spec["content"],
                spec["sig_type"],
                pin,
                set_methods=spec["set_methods"],
                tsa_url=tsa_url if spec["tsa"] else None,
                sign_timeout=float(spec["sign_timeout"]),
            )
            status[f"sign_{name}"] = True
            print(f"OK  Sign → {spec['stem']}.xml ({len(signed)} chars)")

            unsigned_names = unsigned_signature_property_names(signed)
            print(f"    UnsignedSignatureProperties children: {unsigned_names}")

            verify_ok = False
            verify_error: Optional[str] = None
            try:
                verify_signed(
                    session, signed, timeout=float(spec["verify_timeout"])
                )
                verify_ok = True
                status[f"verify_{name}"] = True
                print(f"OK  Verify [{name}]")
            except Exception as exc:
                verify_error = str(exc)
                status[f"verify_{name}"] = False
                status["blockers"].append(f"Verify [{name}] failed: {exc}")
                print(f"FAIL Verify [{name}]: {exc}")

            meta = {
                **base_meta,
                **spec["meta_extra"],
                "verify_ok": verify_ok,
                "verify_error": verify_error,
                "unsigned_signature_properties": unsigned_names,
                "tsa_property": tsa_prop,
            }
            # Always persist signed XML even when Verify fails.
            save_signed_fixture(out_dir, spec["stem"], signed, meta)
            if tsa_prop:
                status.setdefault("tsa_property_used", tsa_prop)
            status.setdefault("unsigned_by_job", {})[name] = unsigned_names
        except Exception as exc:
            status[f"sign_{name}"] = False
            status["blockers"].append(f"Sign [{name}] failed: {exc}")
            print(f"FAIL Sign [{name}]: {exc}")
            if verbose:
                traceback.print_exc()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Produce golden SignedXML fixtures via CryptoPro nmcades NMH"
    )
    parser.add_argument(
        "--nmcades",
        default=os.environ.get("NMCADES", DEFAULT_NMCADES),
        help="path to nmcades binary",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_DOC_URL,
        help="document URL reported to host for trusted-site checks",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=OUT_DIR,
        help="output directory for fixtures",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="sign enveloped XMLDSIG (also enabled by --all)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="produce enveloped + enveloping + template + XAdES-BES/T/XLT1 goldens",
    )
    parser.add_argument(
        "--enveloping",
        action="store_true",
        help="also produce enveloping golden",
    )
    parser.add_argument(
        "--template",
        action="store_true",
        help="also produce template golden",
    )
    parser.add_argument(
        "--xades-bes",
        action="store_true",
        help="also produce XAdES-BES (ENVELOPED|0x20) golden",
    )
    parser.add_argument(
        "--xades-t",
        action="store_true",
        help="also produce XAdES-T (ENVELOPED|0x50) golden with TSA",
    )
    parser.add_argument(
        "--xades-xlt1",
        action="store_true",
        help="also produce XAdES-X Long Type 1 (ENVELOPED|0x5d0) golden with TSA",
    )
    parser.add_argument(
        "--xades-a",
        action="store_true",
        help="also produce XAdES-A (ENVELOPED|0x7d0) golden with TSA",
    )
    parser.add_argument(
        "--tsa",
        default=DEFAULT_TSA_URL,
        help=f"TSA URL for XAdES-T/XLT1/A (default: {DEFAULT_TSA_URL})",
    )
    parser.add_argument("--pin", default=None, help="container PIN (prefer --pin-file / env)")
    parser.add_argument("--pin-file", default=None, help="file containing container PIN")
    parser.add_argument(
        "--cert-thumbprint",
        default=None,
        help="select certificate by thumbprint (hex, case-insensitive)",
    )
    parser.add_argument(
        "--cert-subject",
        default=None,
        help="substring match against SubjectName",
    )
    parser.add_argument(
        "--store-timeout",
        type=float,
        default=25.0,
        help="timeout seconds for Store.Open (UI may hang forever)",
    )
    parser.add_argument(
        "--verify-file",
        type=Path,
        default=None,
        metavar="PATH",
        help="only verify existing SignedXML at PATH (Content + Verify); skip sign/store",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    # Fast path: reverse-interop verify only (no Store / Sign).
    if args.verify_file is not None:
        path: Path = args.verify_file
        if not path.is_file():
            print(f"FAIL: --verify-file not found: {path}", file=sys.stderr)
            return 1
        signed = path.read_text(encoding="utf-8")
        session = NmcadesSession(
            nmcades_path=args.nmcades,
            doc_url=args.url,
            verbose=args.verbose,
            default_timeout=30.0,
        )
        status: Dict[str, Any] = {
            "mode": "verify-file",
            "path": str(path),
            "init": False,
            "verify": False,
            "error": None,
        }
        try:
            print("Connecting to nmcades…")
            plugin_id = session.init()
            status["init"] = True
            print(f"OK  init → plugin objid={plugin_id}")
            print(f"Verify file {path} ({len(signed)} chars)…")
            verify_signed(session, signed, timeout=VERIFY_TIMEOUT_XADES)
            status["verify"] = True
            print(f"OK  Verify {path}")
            return 0
        except Exception as exc:
            status["error"] = str(exc)
            print(f"FAIL Verify {path}: {exc}", file=sys.stderr)
            if args.verbose:
                traceback.print_exc()
            return 1
        finally:
            session.close()
            print("--- summary ---")
            print(json.dumps(status, ensure_ascii=False, indent=2))

    out_dir: Path = args.out_dir
    save_text(out_dir / "input_enveloped.xml", MINIMAL_XML)
    save_text(out_dir / "input_template.xml", TEMPLATE_XML)

    want_sign = (
        args.sign
        or args.all
        or args.enveloping
        or args.template
        or args.xades_bes
        or args.xades_t
        or args.xades_xlt1
        or args.xades_a
    )
    jobs: List[str] = []
    if args.all:
        jobs = [
            "enveloped",
            "enveloping",
            "template",
            "xades_bes",
            "xades_t",
            "xades_xlt1",
            "xades_a",
        ]
    else:
        if args.sign:
            jobs.append("enveloped")
        if args.enveloping:
            jobs.append("enveloping")
        if args.template:
            jobs.append("template")
        if args.xades_bes:
            jobs.append("xades_bes")
        if args.xades_t:
            jobs.append("xades_t")
        if args.xades_xlt1:
            jobs.append("xades_xlt1")
        if args.xades_a:
            jobs.append("xades_a")

    status = {
        "init": False,
        "about": False,
        "about_version": None,
        "signedxml_create": False,
        "store": False,
        "certs": 0,
        "jobs": jobs,
        "tsa_url": args.tsa,
        "blockers": [],
    }

    # Long enough for XLT1 OCSP + TSA; individual Sign/Verify use their own timeouts.
    session_default_timeout = 60.0
    if args.xades_xlt1 or args.xades_a or args.all:
        session_default_timeout = 120.0

    session = NmcadesSession(
        nmcades_path=args.nmcades,
        doc_url=args.url,
        verbose=args.verbose,
        default_timeout=session_default_timeout,
    )
    try:
        print("Connecting to nmcades…")
        plugin_id = session.init()
        status["init"] = True
        print(f"OK  init → plugin objid={plugin_id}")

        about = session.create_object("CAdESCOM.About", timeout=20)
        status["about"] = True
        version = _stringify_version(about)
        status["about_version"] = version
        print(f"OK  CAdESCOM.About Version = {version}")
        print(f"    About props={about.properties} methods={about.methods}")

        sx = session.create_object("CAdESCOM.SignedXML", timeout=20)
        status["signedxml_create"] = True
        print(f"OK  CAdESCOM.SignedXML CreateObject → objid={sx.objid}")
        print(f"    SignedXML props={sx.properties} methods={sx.methods}")

        certs: List[Dict[str, Any]] = []
        try:
            store = session.create_object("CAdESCOM.Store", timeout=20)
            print(f"OK  CAdESCOM.Store CreateObject → objid={store.objid}")
            store.call(
                "Open",
                CAPICOM_CURRENT_USER_STORE,
                CAPICOM_MY_STORE,
                CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED,
                timeout=args.store_timeout,
            )
            status["store"] = True
            certs = list_certificates(store, timeout=args.store_timeout)
            status["certs"] = len(certs)
            print(f"OK  Store.Open + Certificates.Count = {len(certs)}")
            for c in certs:
                print(
                    f"    [{c['index']}] Subject={c.get('SubjectName')!r} "
                    f"Thumbprint={c.get('Thumbprint')!r}"
                )
            try:
                store.call("Close", timeout=10)
            except Exception:
                pass
        except TimeoutError as exc:
            msg = (
                "Store.Open timed out — CryptoPro likely needs interactive UI "
                "(certificate store / trusted site / CSP dialog). "
                "About + SignedXML CreateObject still work without Store."
            )
            status["blockers"].append(msg)
            print(f"FAIL Store: {exc}")
            print(f"BLOCKER: {msg}")
        except NmcadesError as exc:
            msg = (
                f"Store failed: {exc}. Often requires trusted site / interactive "
                "CSP UI; harness remains usable for About + SignedXML CreateObject."
            )
            status["blockers"].append(msg)
            print(f"FAIL Store: {exc}")
            print(f"BLOCKER: {msg}")

        if not want_sign:
            print(
                "Skip sign (pass --sign / --all / --enveloping / --template / "
                "--xades-bes / --xades-t / --xades-xlt1 / --xades-a)."
            )
        elif not certs:
            msg = "Cannot sign: no certificates from Store (or Store unavailable)."
            status["blockers"].append(msg)
            print(f"BLOCKER: {msg}")
        else:
            pin = read_pin(args)
            if not pin:
                print(
                    "WARN: no PIN (--pin / --pin-file / CRYPTOPRO_PIN); "
                    "Sign may pop a UI dialog or fail."
                )
            selected = select_cert(certs, args.cert_thumbprint, args.cert_subject)
            if selected is None:
                status["blockers"].append("certificate selection failed")
            else:
                print(
                    f"Signing with cert Subject={selected.get('SubjectName')!r} "
                    f"Thumbprint={selected.get('Thumbprint')!r}"
                )
                if any(j in ("xades_t", "xades_xlt1", "xades_a") for j in jobs):
                    print(f"TSA URL: {args.tsa}")
                run_sign_jobs(
                    session,
                    selected,
                    pin,
                    out_dir,
                    status["about_version"],
                    args.url,
                    jobs,
                    status,
                    tsa_url=args.tsa,
                    verbose=args.verbose,
                )

    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        if args.verbose:
            traceback.print_exc()
        status["blockers"].append(str(exc))
        return 1
    finally:
        session.close()

    print("--- summary ---")
    print(json.dumps(status, ensure_ascii=False, indent=2))
    if status["init"] and status["about"] and status["signedxml_create"]:
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
