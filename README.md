# Jex

Cross-platform Rust CLI for CryptoPro classic containers (Rutoken Lite / HDIMAGE), CMS/CAdES, XML-DSig/XAdES, GOST CMS EnvelopedData encryption, and a local signing daemon / Native Messaging host.

Supported CAdES flow:

```text
CryptoPro classic container / Rutoken Lite
    -> CAdES-BES
    -> CAdES-T
    -> CAdES-X Long Type 1
    -> CAdES-A (archive-time-stamp-v3 / ATSHashIndexV3)
    -> repeated CAdES-A renewal
```

The XLT1 builder uses the layout required by CryptoPro's offline CAdES-A historical validation: outer `.21/.22/.23/.24` cover the document signer plus both TSA signers and their revocation evidence. The CAdES-C timestamp is built in two passes because its own TSA signer must be known before final `.21/.22` can be timestamped.

## Installation

Prebuilt binaries for Linux (x86_64, aarch64) and macOS (Intel, Apple Silicon), Debian/Ubuntu packages and a `SHA256SUMS` file are attached to every [GitHub release](https://github.com/jex-crypto/jex/releases).

Talking to a Rutoken requires a PC/SC service: macOS ships one; on Linux and FreeBSD install and start `pcscd` (pcsc-lite) together with the CCID driver.

### Homebrew (macOS, Linux)

```bash
brew install jex-crypto/jex/jex
```

### Debian / Ubuntu

```bash
sudo apt install ./jex_<version>-1_amd64.deb    # or _arm64.deb
sudo systemctl enable --now pcscd.socket
```

The package depends on `libpcsclite1` and recommends `pcscd`.

### Arch Linux

The AUR packages `jex` and `jex-bin` are not published yet. Until then build from the PKGBUILDs in this repository:

```bash
git clone https://github.com/jex-crypto/jex && cd jex/packaging/arch
makepkg -si                       # build from source
(cd jex-bin && makepkg -si)       # or: prebuilt release binary
sudo pacman -S ccid && sudo systemctl enable --now pcscd.socket
```

### FreeBSD

The port is maintained in this repository under `packaging/freebsd` until it is accepted into the ports tree:

```bash
git clone https://github.com/jex-crypto/jex
cp -R jex/packaging/freebsd/security/jex /usr/ports/security/jex
cd /usr/ports/security/jex && make install clean
sysrc pcscd_enable=YES && service pcscd start
```

The `GUI` port option (on by default) controls the graphical PIN dialog of the browser host.

### Prebuilt tarball

```bash
tar -xzf jex-<version>-<target>.tar.gz
sudo install -m 755 jex-<version>-<target>/jex /usr/local/bin/jex
```

On Linux the binary needs `libpcsclite.so.1` at run time.

### From source

Requires Rust 1.88 or newer. On Linux also install `pkg-config` and the pcsc-lite headers (`libpcsclite-dev` on Debian/Ubuntu, `pcsclite` on Arch, `pcsc-lite-devel` on Fedora).

```bash
cargo install --locked --git https://github.com/jex-crypto/jex
```

The default `nmcades-ui` feature builds a native PIN dialog for the browser host; use `--no-default-features` for a headless build.

See `packaging/README.md` for packaging and release details.

## Build

```bash
cargo build --release
cargo test
```

Linux requires PC/SC development/runtime packages. macOS uses the system PC/SC framework. Windows uses WinSCard through the `pcsc` crate.

## Commands

| Command | Role |
|---------|------|
| `hdimage` | Inspect / unlock six-file containers on disk |
| `rutoken` | List/tree/containers/dump/inspect/unlock on card |
| `cades` | Sign, enhance, archive, attach/detach, audit, verify |
| `encrypt` / `decrypt` | CMS EnvelopedData (GOST + VKO) |
| `xml` | XML-DSig / XAdES sign, verify, inspect |
| `daemon` | HTTP signing API (`examples/daemon.json`) |
| `nmcades-host` | Chrome/Safari Native Messaging host (CryptoPro plug-in stand-in) |

## Rutoken / classic container

```bash
jex rutoken list
jex rutoken tree --max-depth 4
jex rutoken containers
```

Read a discovered container to disk:

```bash
jex rutoken dump \
  --index 0 \
  --token-pin-file rutoken.pin \
  --out container-dir
```

Inspect or unlock an already dumped six-file container:

```bash
jex hdimage inspect container-dir
jex hdimage unlock container-dir --pin-file container.pin
```

Private key material is not printed by default and is zeroized after use.

## List signing certificates

```bash
jex cades certificates \
  --token-pin-file rutoken.pin
```

## CAdES-BES

Detached:

```bash
jex cades sign document.pdf \
  --out document.pdf.sig \
  --index 0 \
  --token-pin-file rutoken.pin \
  --container-pin-file container.pin
```

Attached:

```bash
jex cades sign document.pdf \
  --attached \
  --out document.p7s \
  --index 0 \
  --token-pin-file rutoken.pin \
  --container-pin-file container.pin
```

## CAdES-T

```bash
jex cades sign document.pdf \
  --out document.pdf.t.sig \
  --index 0 \
  --token-pin-file rutoken.pin \
  --container-pin-file container.pin \
  --tsa 'https://tsa.example/tsp'
```

The RFC 3161 request uses the CMS signature value as the timestamped input. Before embedding `id-aa-signatureTimeStampToken` (`1.2.840.113549.1.9.16.2.14`), the implementation validates the returned message imprint and nonce, resolves the TSA signer certificate from `SignerInfo.sid`, verifies the timestamp token's signed attributes and GOST CMS signature, and checks signer-certificate validity at `genTime`.

## CAdES-X Long Type 1

Upgrade an existing CAdES-T. No private key or Rutoken is used in this step:

```bash
jex cades enhance document.pdf.t.sig \
  --out document.pdf.xlong.sig \
  --tsa 'https://tsa.example/tsp'
```

Validation data are normally collected from HTTP(S) AIA/OCSP/CRL URLs. Manual/offline inputs are also supported:

```bash
jex cades enhance document.pdf.t.sig \
  --out document.pdf.xlong.sig \
  --tsa 'https://tsa.example/tsp' \
  --chain-cert intermediate.cer \
  --chain-cert root.cer \
  --ocsp-file signer.ocsp \
  --crl intermediate.crl \
  --no-fetch-validation
```

The final outer unsigned attributes are:

- `.21` `completeCertificateRefs`;
- `.22` `completeRevocationRefs`;
- `.23` `certificateValues`;
- `.24` `revocationValues`;
- `.25` CAdES-C / `escTimeStamp`.

For CryptoPro CAdES-A interoperability, the outer refs/values include:

- document signer chain/status;
- signature timestamp TSA signer chain/status;
- CAdES-C timestamp TSA signer chain/status;
- delegated OCSP responder certificates where present.

The `.25` TSA is discovered with a provisional timestamp; final `.21/.22` are then rebuilt and a new final `.25` is requested over the completed refs. The provisional token is never embedded.

## CAdES-A / ATSv3

Add the first archive timestamp:

```bash
jex cades archive document.pdf.xlong.sig \
  --content document.pdf \
  --out document.pdf.a.sig \
  --tsa 'https://tsa.example/tsp'
```

Renew an existing CAdES-A with another archive timestamp:

```bash
jex cades archive document.pdf.a.sig \
  --content document.pdf \
  --out document.pdf.a2.sig \
  --tsa 'https://tsa.example/tsp'
```

For detached CAdES-A, ATSv3 only embeds `H(content)` (= `messageDigest` when digest OIDs match). You can pass that hex digest instead of the file:

```bash
jex cades archive document.pdf.xlong.sig \
  --content-hash <HEX> \
  --out document.pdf.a.sig \
  --tsa 'https://tsa.example/tsp'
```

(`--content` and `--content-hash` are mutually exclusive. Same options apply to `cades audit` / `cades verify`.)

Implemented modern ETSI attributes:

- `archive-time-stamp-v3`: `0.4.0.1733.2.4`;
- `ATSHashIndexV3`: `0.4.0.19122.1.5`.

Each renewal protects the historical unsigned-attribute snapshot that existed before that archive timestamp. Archive timestamps must have strictly increasing `genTime`.

## Detached ↔ attached conversion

Convert without changing `SignerInfo` or any unsigned attribute. `messageDigest` is checked; the result is profile-verified before write (including ATSv3 for CAdES-A).

Detached → attached:

```bash
jex cades attach document.pdf.a.sig \
  --content document.pdf \
  --out document.p7s
```

Attached → detached (optional `--content-out` writes the extracted file):

```bash
jex cades detach document.p7s \
  --out document.pdf.a.sig \
  --content-out document.pdf
```

## Inspect

```bash
jex cades inspect document.pdf.a.sig
```

`inspect` prints the detected profile, timestamp metadata, XLT1 markers and local semantic audit results without establishing PKI trust.

## Verify

Detached (file or digest):

```bash
jex cades verify document.pdf.a.sig --content document.pdf
jex cades verify document.pdf.a.sig --content-hash <HEX>
```

Attached:

```bash
jex cades verify document.p7s
```

`verify` is profile-aware. It performs all locally implemented checks:

1. **BES**: document `messageDigest`, `SigningCertificateV2`, `SignerIdentifier`, GOST signature over signed attributes;
2. **T**: RFC 3161 signature-timestamp `messageImprint` over the CMS signature value, signed `content-type`/`message-digest`, TSA `SignerInfo.sid`, GOST CMS signature, and signer-certificate validity at `genTime`;
3. **XLT1**: required attributes, refs-to-values mapping, document-signer OCSP constraints, nested TSA evidence, mandatory outer OCSP bindings for both TSA signers (CryptoPro offline CAdES-A compatibility), CAdES-C timestamp imprint and CAdES-C timestamp CMS/GOST signature;
4. **A**: every `ATSHashIndexV3`, archive timestamp `messageImprint`, historical unsigned-attribute snapshots, archive chronology, every archive RFC 3161 CMS/GOST signature, and the XLT1 base.

A partial XLT1 attribute set is rejected rather than silently treated as CAdES-T/BES.

The local verifier does **not** independently establish PKI trust anchors, certificate-chain signatures, or revocation-policy decisions. It does verify the embedded RFC 3161 token signatures cryptographically. Use CryptoPro or another trusted PKI validator for final trust-policy validation.

## Semantic audit

```bash
jex cades audit document.pdf.xlong.sig
jex cades audit document.pdf.a.sig --content document.pdf
jex cades audit document.pdf.a.sig --content-hash <HEX>
```

## Encrypt / decrypt (CMS EnvelopedData)

Symmetric content encryption with GOST VKO key agreement to one or more recipient certificates:

```bash
jex encrypt document.pdf \
  --recipient-cert bob.cer \
  --alg gost28147 \
  --out document.pdf.p7e
```

`--alg`: `gost28147` (default), `magma`, `kuznyechik` (aliases `25` / `35` / `45`).

Decrypt with a classic container (disk or Rutoken):

```bash
jex decrypt document.pdf.p7e \
  --container-dir container-dir \
  --container-pin-file container.pin \
  --out document.pdf
```

## XML-DSig / XAdES

```bash
jex xml sign document.xml \
  --out document.signed.xml \
  --type enveloped \
  --profile bes \
  --index 0 \
  --token-pin-file rutoken.pin \
  --container-pin-file container.pin

jex xml verify document.signed.xml
jex xml inspect document.signed.xml
```

`--profile`: `xmldsig` | `bes` | `t` | `xlt1` | `a` (`t` / `xlt1` / `a` need `--tsa`). `--type`: `enveloped` | `enveloping` | `template`.

Add or renew an archive timestamp on an existing XAdES-XLT1/A document (no private key):

```bash
jex xml archive document.xlt1.xml \
  --out document.a.xml \
  --tsa 'https://tsa.example/tsp'
```

CryptoPro CADESCOM reverse-check for XMLDSig through XAdES-XLT1 (`cryptcp`
does not verify XML):

```bash
scripts/cryptopro-xml-verify.sh document.xlt1.xml
```

CryptoPro SVS online (forces `UseXades`, unlike the web UI default):

```bash
python3 scripts/cryptopro-svs-verify.py testdata/xmldsig/jex_xades_a.xml
python3 scripts/cryptopro-svs-verify.py --report-out /tmp/svs.pdf testdata/xmldsig/jex_xades_a.xml
```

Jex emits the ETSI XAdES 1.4.1 form, `xades141:ArchiveTimeStamp`. CryptoPro
libxades 2.0.15700 recognizes that property as `XADES_A` (`0x7d0`), but its
profile verification can still return `XADES_VERIFY_NO_CHAIN`; generic
`SignedXML.Verify` is not an XAdES-A conformance check. The deprecated 1.3.2
`xades:ArchiveTimeStamp` may pass generic verification, but CryptoPro classifies
that document only as XAdES-XLT1, so Jex does not emit it as XAdES-A.

## HTTP daemon

Unlock containers once and serve signing over HTTP:

```bash
jex daemon --config examples/daemon.json
# optional: --listen 127.0.0.1:8787
```

Auth: `Authorization: Bearer <token>` or allowed browser `Origin` from `api_keys` in the config.

For web pages use the first-party API (no CryptoPro CADESCOM):

- [`docs/api-v1.md`](docs/api-v1.md) — `/api/v1/*`
- SDK: `http://127.0.0.1:8787/jex.js` (`Jex.create({ baseUrl, token })`)

Legacy `/v1/*` and frozen CryptoPro shim `/nmcades/*` (+ `cadesplugin_api.js`): [`docs/daemon-api.md`](docs/daemon-api.md).

## Native Messaging host

Drop-in stand-in for CryptoPro `nmcades` (same config shape as the daemon):

```bash
jex nmcades-host --config examples/daemon.json
# Safari localhost bridge: --http 127.0.0.1:18787
# Prefer LaunchAgent (Safari cannot spawn NMH): ./scripts/install-nmcades-http.sh
```

## Certificate revocation checking

`rutoken containers` and `rutoken inspect` show each certificate's date validity and OCSP revocation status, backed by an on-disk cache (`~/.cache/jex/cert-cache.json` on Linux/macOS) so repeat invocations avoid re-reading the Rutoken filesystem or re-querying OCSP within the cache TTL:

```bash
jex rutoken containers            # normal run: uses cache, checks the network when needed
jex rutoken containers --offline  # never touch the network; only report already-cached results
jex rutoken containers --refresh  # force a fresh certificate + revocation check, bypassing the cache
```

Certificates already expired (or not yet valid) are never revocation-checked — an expired certificate cannot be trusted regardless of its OCSP status, so this saves a needless network round trip.

Internally this is implemented by `certcache::CertCache` (container certificate + OCSP result caching with TTL) and `validation::check_certificate()`, which returns an `x509::CertCheck { validity, revocation_status }`.

Revocation checks are cached per (certificate serial, issuer name) with separate TTL for good status (24h default) vs. unknown/error (1h default). Caching is especially useful when checking multiple signatures from the same issuer.

The local verifier does **not** establish revocation policy — revocation status is returned separately from signature validity. Use the revocation result in conjunction with your trust-policy requirements.

## CryptoPro interoperability

The final two-pass XLT1 + ATSv3 layout was verified with CryptoPro CryptCP 5.0 / CAdES library 2.0.15700:

```bash
/opt/cprocsp/bin/cryptcp \
  -verify -detached -xlongtype1 \
  document.pdf document.pdf.xlong.sig

/opt/cprocsp/bin/cryptcp \
  -verify -detached -cadesa \
  document.pdf document.pdf.a.sig
```

Both paths return `Подпись проверена`; `-cadesa` reports the signature timestamp, CAdES-C evidence timestamp and archive timestamp.

Smoke test helper (needs CryptCP on the machine):

```bash
scripts/cryptopro-verify.sh document.pdf document.pdf.xlong.sig document.pdf.a.sig
# if cryptcp is not at /opt/cprocsp/bin/cryptcp:
CRYPTCP=/path/to/cryptcp scripts/cryptopro-verify.sh …
```

## CMS algorithm identifiers

For GOST R 34.10-2012/256, generated CMS `SignerInfo` uses:

```text
digestAlgorithm    = 1.2.643.7.1.1.2.2
signatureAlgorithm = 1.2.643.7.1.1.1.1
```

The combined X.509 `signWithDigest` OID is accepted by the local verifier for legacy input but is not emitted for new CMS signatures.


## License

Copyright (C) Roman Yerin.

Jex is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version (`AGPL-3.0-or-later`). See [`LICENSE`](LICENSE) for the full text.

Jex is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
