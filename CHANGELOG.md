# Changelog

## 0.13.2

- Security: OCSP responses are now authenticated before they are trusted for revocation status or embedded into CAdES-X Long Type 1. A response must be signed by the issuing CA or by a delegated responder certificate issued by that CA with `id-kp-OCSPSigning` and valid at `producedAt` (RFC 6960 §4.2.2.2). Previously a forged "good" response over plain HTTP was accepted.
- Live OCSP responses are checked for freshness: `thisUpdate` at most 10 minutes ahead, and either `nextUpdate` not passed or, without `nextUpdate`, `thisUpdate` within the last hour.
- CA CRLs collected for XLT1 must verify against the next CA in the chain.
- `cades verify` prints the chain root and states that it is not checked against a trusted root list.

## 0.13.1

- GOST R 34.10-2012 signing now derives the per-signature nonce `k` with RFC 6979 HMAC_DRBG over HMAC-Streebog-512 (RFC 7836), seeded with the private key, the digest and fresh OS entropy. A weak or repeating system RNG can no longer leak the private key through a reused `k`.

## 0.13.0

- Consolidated the proven CryptoPro-compatible CAdES-X Long Type 1 construction into the default `cades enhance` path.
- Removed experimental compatibility flags, promotion probes and A/B-test code.
- XLT1 enhancement now always uses a provisional `.25` to discover its TSA signer, then issues the final `.25` over complete outer TSA/document-signer refs.
- Kept nested timestamp validation evidence for signature, CAdES-C and archive timestamp tokens.
- Kept modern `archive-time-stamp-v3` / `ATSHashIndexV3` generation and renewal.
- Strengthened XLT1 audit for mandatory outer OCSP bindings of both TSA signers, plus empty refs (`self-issued` or `id-pkix-ocsp-nocheck`).
- Made `cades verify` profile-aware: BES, T, XLT1 and A are checked at the strongest locally implemented level.
- Added cryptographic CMS/GOST verification for signature, CAdES-C and archive RFC 3161 timestamp tokens, including `messageDigest`/`contentType`, signer binding and certificate validity at `genTime`.
- Added one profile-aware verification core reused by `cades verify` and post-conversion checks.
- Restored detached-to-attached conversion as a production `cades attach` command; it preserves SignerInfo/unsigned attributes byte-for-byte and verifies the resulting profile before writing.
- Removed nonconformant long-term-signature escape hatches from the production CLI.

## Compatibility

Final XLT1 and CAdES-A outputs have been accepted by CryptoPro CryptCP (`-xlongtype1`, `-cadesa`) using CSP 5.0.13800 / CAdES 2.0.15700.
