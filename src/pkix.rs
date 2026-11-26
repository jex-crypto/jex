// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Soft PKIX crypto for CAdES: RSA-2048 + SHA-256 and ECDSA P-256 + SHA-256
//! for signing; verification also accepts SHA-384 / SHA-512 (e.g. TSA tokens).
//!
//! GOST / Rutoken paths stay in `gost3410` + classic containers. This module
//! covers PEM PKCS#8 (and PKCS#1 / SEC1) private keys used for EU / ICP-Brasil
//! style CMS signatures.

use crate::{cades, cms_der, der, x509};
use anyhow::{bail, Context, Result};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use p256::EncodedPoint;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;
use zeroize::Zeroizing;

pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SHA384: &str = "2.16.840.1.101.3.4.2.2";
pub const OID_SHA512: &str = "2.16.840.1.101.3.4.2.3";
pub const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
pub const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
pub const OID_SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
pub const OID_SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
pub const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
pub const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
pub const OID_ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";
pub const OID_ECDSA_WITH_SHA512: &str = "1.2.840.10045.4.3.4";
pub const OID_SECP256R1: &str = "1.2.840.10045.3.1.7";

/// Soft private key. Not `Clone`: the wrapped `RsaPrivateKey` / p256
/// `SigningKey` zeroize their secret material on drop, so dropping this
/// value is sufficient to erase the key.
#[derive(Debug)]
pub enum SoftPrivateKey {
    Rsa(RsaPrivateKey),
    EcdsaP256(EcdsaSigningKey),
}

impl SoftPrivateKey {
    pub fn from_pem_bytes(pem: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(pem).context("private key PEM is not UTF-8")?;
        Self::from_pem(text)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        if let Ok(k) = RsaPrivateKey::from_pkcs8_pem(pem) {
            return Ok(Self::Rsa(k));
        }
        if let Ok(k) = RsaPrivateKey::from_pkcs1_pem(pem) {
            return Ok(Self::Rsa(k));
        }
        if let Ok(k) = EcdsaSigningKey::from_pkcs8_pem(pem) {
            return Ok(Self::EcdsaP256(k));
        }
        if let Ok(secret) = p256::SecretKey::from_sec1_pem(pem) {
            return Ok(Self::EcdsaP256(EcdsaSigningKey::from(secret)));
        }
        bail!("unsupported private key PEM (need RSA or P-256 PKCS#8 / PKCS#1 / SEC1)");
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = Zeroizing::new(
            std::fs::read(path)
                .with_context(|| format!("read private key {}", path.display()))?,
        );
        Self::from_pem_bytes(&raw)
    }

    pub fn matches_certificate(&self, cert_der: &[u8]) -> Result<bool> {
        let spk = x509::subject_public_key(cert_der)?;
        Ok(match (self, spk) {
            (Self::Rsa(sk), x509::SubjectPublicKey::Rsa { modulus, exponent }) => {
                let pk = sk.to_public_key();
                integer_bytes_eq(pk.n(), &modulus) && integer_bytes_eq(pk.e(), &exponent)
            }
            (Self::EcdsaP256(sk), x509::SubjectPublicKey::EcP256 { uncompressed }) => {
                let point = EncodedPoint::from(sk.verifying_key());
                point.as_bytes() == uncompressed.as_slice()
            }
            _ => false,
        })
    }

    pub fn digest_oid(&self) -> &'static str {
        OID_SHA256
    }

    pub fn signature_oid(&self) -> &'static str {
        match self {
            Self::Rsa(_) => OID_RSA_ENCRYPTION,
            Self::EcdsaP256(_) => OID_ECDSA_WITH_SHA256,
        }
    }

    /// Sign CMS signedAttrs (hash-then-sign per algorithm OID).
    pub fn sign_signed_attrs(&self, signed_attrs_der: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Rsa(sk) => {
                // Sign in place (no clone of the private key); the RNG is only
                // used for blinding, PKCS#1 v1.5 itself is deterministic.
                let hashed = Sha256::digest(signed_attrs_der);
                sk.sign_with_rng(
                    &mut rand::thread_rng(),
                    Pkcs1v15Sign::new::<Sha256>(),
                    &hashed,
                )
                .context("RSA PKCS#1 v1.5 signing failed")
            }
            Self::EcdsaP256(sk) => {
                let sig: EcdsaSignature = sk.sign(signed_attrs_der);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }
}

fn integer_bytes_eq(n: &rsa::BigUint, der_int: &[u8]) -> bool {
    let a = n.to_bytes_be();
    let b = strip_leading_zeros(der_int);
    strip_leading_zeros(&a) == b
}

fn strip_leading_zeros(v: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < v.len() && v[i] == 0 {
        i += 1;
    }
    &v[i..]
}

/// Hash OID implied by an RSA/ECDSA signatureAlgorithm OID, or `None` for a
/// bare public-key OID (rsaEncryption / id-ecPublicKey) that defers to
/// SignerInfo.digestAlgorithm.
fn signature_oid_hash(signature_oid: &str) -> Option<&'static str> {
    match signature_oid {
        OID_SHA256_WITH_RSA | OID_ECDSA_WITH_SHA256 => Some(OID_SHA256),
        OID_SHA384_WITH_RSA | OID_ECDSA_WITH_SHA384 => Some(OID_SHA384),
        OID_SHA512_WITH_RSA | OID_ECDSA_WITH_SHA512 => Some(OID_SHA512),
        _ => None,
    }
}

/// Verify an RSA PKCS#1 v1.5 or ECDSA P-256 signature over CMS signedAttrs.
///
/// `digest_oid` is SignerInfo.digestAlgorithm (SHA-256/384/512). A
/// signatureAlgorithm that names a different hash is rejected with an error,
/// as is a signatureAlgorithm that does not fit the certificate key.
pub fn verify_signed_attrs(
    spk: &x509::SubjectPublicKey,
    digest_oid: &str,
    signature_oid: &str,
    signed_attrs_der: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if !matches!(digest_oid, OID_SHA256 | OID_SHA384 | OID_SHA512) {
        bail!("digestAlgorithm {digest_oid} is not supported for RSA/ECDSA (need SHA-256/384/512)");
    }
    if let Some(sig_hash) = signature_oid_hash(signature_oid) {
        if sig_hash != digest_oid {
            bail!(
                "signatureAlgorithm {signature_oid} implies digest {sig_hash}, but digestAlgorithm is {digest_oid}"
            );
        }
    }
    let hashed = cades::digest_by_oid(digest_oid, signed_attrs_der)?;
    match spk {
        x509::SubjectPublicKey::Rsa { modulus, exponent } => {
            if !matches!(
                signature_oid,
                OID_RSA_ENCRYPTION | OID_SHA256_WITH_RSA | OID_SHA384_WITH_RSA | OID_SHA512_WITH_RSA
            ) {
                bail!(
                    "signatureAlgorithm {signature_oid} does not match RSA certificate key"
                );
            }
            let n = rsa::BigUint::from_bytes_be(strip_leading_zeros(modulus));
            let e = rsa::BigUint::from_bytes_be(strip_leading_zeros(exponent));
            let pk = RsaPublicKey::new(n, e).context("rebuild RSA public key from certificate")?;
            let scheme = match digest_oid {
                OID_SHA256 => Pkcs1v15Sign::new::<Sha256>(),
                OID_SHA384 => Pkcs1v15Sign::new::<Sha384>(),
                _ => Pkcs1v15Sign::new::<Sha512>(),
            };
            Ok(pk.verify(scheme, &hashed, signature).is_ok())
        }
        x509::SubjectPublicKey::EcP256 { uncompressed } => {
            if !matches!(
                signature_oid,
                OID_EC_PUBLIC_KEY
                    | OID_ECDSA_WITH_SHA256
                    | OID_ECDSA_WITH_SHA384
                    | OID_ECDSA_WITH_SHA512
            ) {
                bail!(
                    "signatureAlgorithm {signature_oid} does not match ECDSA P-256 certificate key"
                );
            }
            let point = EncodedPoint::from_bytes(uncompressed)
                .context("parse P-256 public point from certificate")?;
            let vk = VerifyingKey::from_encoded_point(&point)
                .map_err(|e| anyhow::anyhow!("invalid P-256 public key: {e}"))?;
            let sig =
                EcdsaSignature::from_der(signature).context("parse ECDSA signature (DER)")?;
            // SHA-384/512 prehashes are truncated to the field size (FIPS 186-4).
            Ok(vk.verify_prehash(&hashed, &sig).is_ok())
        }
        x509::SubjectPublicKey::Gost { .. } => {
            bail!("use gost3410 verification for GOST certificates")
        }
    }
}

/// AlgorithmIdentifier with explicit NULL parameters (common for rsaEncryption).
pub fn algorithm_identifier_null(oid_text: &str) -> Result<Vec<u8>> {
    Ok(cms_der::sequence(&[cms_der::oid(oid_text)?, cms_der::tlv(0x05, &[])]))
}

/// First AlgorithmIdentifier OID inside SubjectPublicKeyInfo.
pub fn spki_algorithm_oid(spki_der: &[u8]) -> Result<String> {
    let spki = der::parse_tlv(spki_der).context("parse SubjectPublicKeyInfo")?;
    if spki.tag != 0x30 {
        bail!("SubjectPublicKeyInfo is not a SEQUENCE");
    }
    let parts = x509::raw_children(spki.value)?;
    let alg = der::parse_tlv(*parts.first().context("SPKI missing algorithm")?)?;
    if alg.tag != 0x30 {
        bail!("SPKI algorithm is not AlgorithmIdentifier");
    }
    let alg_parts = x509::raw_children(alg.value)?;
    let oid = der::parse_tlv(*alg_parts.first().context("AlgorithmIdentifier missing OID")?)?;
    if oid.tag != 0x06 {
        bail!("AlgorithmIdentifier OID is not OBJECT IDENTIFIER");
    }
    der::decode_oid(oid.value).context("decode SPKI algorithm OID")
}
