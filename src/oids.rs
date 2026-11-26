// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::curves;

/// Return a short human-readable label for a known OID, if any.
pub fn describe(oid: &str) -> Option<&'static str> {
    if let Some(curve) = curves::by_oid(oid) {
        return Some(curve.name);
    }

    Some(match oid {
        // GOST R 34.10-2012 / Streebog (TC26, RFC 9215)
        "1.2.643.7.1.1.1.1" => "GOST R 34.10-2012 256-bit public key",
        "1.2.643.7.1.1.1.2" => "GOST R 34.10-2012 512-bit public key",
        "1.2.643.7.1.1.2.2" => "Streebog-256 (GOST R 34.11-2012)",
        "1.2.643.7.1.1.2.3" => "Streebog-512 (GOST R 34.11-2012)",
        "1.2.643.7.1.1.3.2" => "GOST R 34.10-2012 256-bit signature with Streebog-256",
        "1.2.643.7.1.1.3.3" => "GOST R 34.10-2012 512-bit signature with Streebog-512",
        "1.2.643.7.1.1.4.1" => "GOST R 34.10-2012 256-bit VKO key agreement",
        "1.2.643.7.1.1.4.2" => "GOST R 34.10-2012 512-bit VKO key agreement",
        "1.2.643.7.1.1.5.1" => "GOST R 34.11-2012 256-bit HMAC",
        "1.2.643.7.1.1.5.2" => "GOST R 34.11-2012 512-bit HMAC",
        "1.2.643.7.1.1.6.1" => "GOST R 34.10-2012 256-bit private key container",
        "1.2.643.7.1.1.6.2" => "GOST R 34.10-2012 512-bit private key container",
        // Legacy GOST
        "1.2.643.2.2.3" => "GOST R 34.10-2001 public key",
        "1.2.643.2.2.9" => "GOST 28147-89",
        "1.2.643.2.2.19" => "GOST R 34.10-2001 key transport",
        "1.2.643.3.2.2" => "GOST R 34.11-94",
        // CryptoPro
        "1.2.643.100.1" => "CryptoPro CSP",
        "1.2.643.100.113" => "CryptoPro organization identifier",
        // PKCS / CMS
        "1.2.840.113549.1.1.1" => "RSA encryption",
        "1.2.840.113549.1.1.5" => "SHA-1 with RSA",
        "1.2.840.113549.1.1.11" => "SHA-256 with RSA",
        "1.2.840.113549.1.1.12" => "SHA-384 with RSA",
        "1.2.840.113549.1.1.13" => "SHA-512 with RSA",
        "1.2.840.10045.2.1" => "elliptic curve public key",
        "1.2.840.10045.3.1.7" => "NIST P-256 (secp256r1)",
        "1.2.840.10045.4.3.2" => "ECDSA with SHA-256",
        "1.2.840.10045.4.3.3" => "ECDSA with SHA-384",
        "1.2.840.10045.4.3.4" => "ECDSA with SHA-512",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        "1.2.840.113549.1.7.1" => "PKCS#7 data",
        "1.2.840.113549.1.7.2" => "PKCS#7 signedData",
        "1.2.840.113549.1.9.3" => "contentType",
        "1.2.840.113549.1.9.4" => "messageDigest",
        // PKIX
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.6.1.5.5.7.48.1" => "OCSP",
        "1.3.6.1.5.5.7.48.1.1" => "OCSP basic response",
        "1.3.6.1.5.5.7.48.1.5" => "OCSP noCheck",
        "1.3.6.1.5.5.7.48.2" => "caIssuers",
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.37" => "extendedKeyUsage",
        _ => return None,
    })
}
