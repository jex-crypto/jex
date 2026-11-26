// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! CMS EnvelopedData with GOST R 34.10-2012 VKO + content encryption.
//!
//! Content algorithms:
//! - GOST 28147-89 CFB (CryptoPro default)
//! - Magma CTR-ACPKM (`1.2.643.7.1.1.5.1.1`)
//! - Kuznyechik CTR-ACPKM (`1.2.643.7.1.1.5.2.1`)
//!
//! Key transport stays CryptoPro-style `KeyTransRecipientInfo` + None-KeyWrap
//! (GOST 28147), independent of the content cipher.

use crate::{cms_der, curves, der, gost28147, gost3410, gost3412, x509};
use anyhow::{bail, Context, Result};
use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use streebog::{Digest, Streebog256, Streebog512};
use zeroize::Zeroize;

pub const OID_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
pub const OID_DATA: &str = "1.2.840.113549.1.7.1";
pub const OID_GOST28147_CFB: &str = "1.2.643.2.2.21";
pub const OID_GOST28147_PARAM_Z: &str = "1.2.643.7.1.2.5.1.1";
pub const OID_MAGMA_CTR_ACPKM: &str = "1.2.643.7.1.1.5.1.1";
pub const OID_KUZNYECHIK_CTR_ACPKM: &str = "1.2.643.7.1.1.5.2.1";
pub const OID_NONE_KEY_WRAP: &str = "1.2.643.2.2.13.0";
pub const OID_VKO_256: &str = "1.2.643.7.1.1.4.1";
pub const OID_VKO_512: &str = "1.2.643.7.1.1.4.2";
pub const OID_PUB_256: &str = "1.2.643.7.1.1.1.1";
pub const OID_PUB_512: &str = "1.2.643.7.1.1.1.2";

/// CADESCOM_ENCRYPTION_ALGORITHM_* / CLI `--alg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentAlg {
    #[default]
    Gost28147Cfb,
    MagmaCtrAcpkm,
    KuznyechikCtrAcpkm,
}

impl ContentAlg {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gost28147" | "gost" | "28147" | "25" => Ok(Self::Gost28147Cfb),
            "magma" | "35" => Ok(Self::MagmaCtrAcpkm),
            "kuznyechik" | "kuz" | "кузнечик" | "45" => Ok(Self::KuznyechikCtrAcpkm),
            "magma-omac" | "36" | "kuznyechik-omac" | "kuz-omac" | "46" => {
                bail!("OMAC content encryption ({s}) is not implemented yet")
            }
            other => bail!(
                "unknown --alg {other:?} (expected gost28147|magma|kuznyechik, or 25|35|45)"
            ),
        }
    }

    /// CryptoPro / CADESCOM numeric Algorithm.Name.
    pub fn from_cadescom(n: u32) -> Result<Self> {
        match n {
            0 | 25 => Ok(Self::Gost28147Cfb),
            35 => Ok(Self::MagmaCtrAcpkm),
            45 => Ok(Self::KuznyechikCtrAcpkm),
            36 | 46 => bail!("OMAC content encryption (CADESCOM {n}) is not implemented yet"),
            other => bail!("unsupported CADESCOM encryption algorithm {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gost28147Cfb => "gost28147",
            Self::MagmaCtrAcpkm => "magma",
            Self::KuznyechikCtrAcpkm => "kuznyechik",
        }
    }

    fn oid(self) -> &'static str {
        match self {
            Self::Gost28147Cfb => OID_GOST28147_CFB,
            Self::MagmaCtrAcpkm => OID_MAGMA_CTR_ACPKM,
            Self::KuznyechikCtrAcpkm => OID_KUZNYECHIK_CTR_ACPKM,
        }
    }

    fn from_oid(oid: &str) -> Result<Self> {
        match oid {
            OID_GOST28147_CFB => Ok(Self::Gost28147Cfb),
            OID_MAGMA_CTR_ACPKM => Ok(Self::MagmaCtrAcpkm),
            OID_KUZNYECHIK_CTR_ACPKM => Ok(Self::KuznyechikCtrAcpkm),
            other => bail!("unsupported contentEncryptionAlgorithm {other}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RecipientKey {
    pub cert_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DecryptKey {
    pub private_le: Vec<u8>,
    pub curve: curves::Curve,
    pub cert_der: Vec<u8>,
}

impl Drop for DecryptKey {
    fn drop(&mut self) {
        self.private_le.zeroize();
    }
}

/// Encrypt `plaintext` for GOST recipients → CMS ContentInfo DER.
pub fn encrypt(plaintext: &[u8], recipients: &[RecipientKey]) -> Result<Vec<u8>> {
    encrypt_with(plaintext, recipients, ContentAlg::Gost28147Cfb)
}

pub fn encrypt_with(
    plaintext: &[u8],
    recipients: &[RecipientKey],
    alg: ContentAlg,
) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        bail!("at least one recipient is required");
    }
    let mut cek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut cek);

    let (content_enc_alg, ciphertext) = match alg {
        ContentAlg::Gost28147Cfb => {
            let mut iv = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut iv);
            let ciphertext =
                gost28147::encrypt_cfb(&cek, &iv, plaintext, &gost28147::SBOX_TC26_Z);
            let enc_params = cms_der::sequence(&[
                cms_der::octet_string(&iv),
                cms_der::oid(OID_GOST28147_PARAM_Z)?,
            ]);
            (
                cms_der::sequence(&[cms_der::oid(alg.oid())?, enc_params]),
                ciphertext,
            )
        }
        ContentAlg::MagmaCtrAcpkm => {
            // UKM 12 bytes; IV = ukm[0..4]
            let mut ukm = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut ukm);
            let mut iv = [0u8; 4];
            iv.copy_from_slice(&ukm[..4]);
            let ciphertext =
                gost3412::magma_ctr_acpkm(&cek, &iv, plaintext, gost3412::CMS_MAGMA_SECTION)?;
            let enc_params = cms_der::sequence(&[cms_der::octet_string(&ukm)]);
            (
                cms_der::sequence(&[cms_der::oid(alg.oid())?, enc_params]),
                ciphertext,
            )
        }
        ContentAlg::KuznyechikCtrAcpkm => {
            // UKM 16 bytes; IV = ukm[0..8]
            let mut ukm = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut ukm);
            let mut iv = [0u8; 8];
            iv.copy_from_slice(&ukm[..8]);
            let ciphertext = gost3412::kuznyechik_ctr_acpkm(
                &cek,
                &iv,
                plaintext,
                gost3412::CMS_KUZNYECHIK_SECTION,
            )?;
            let enc_params = cms_der::sequence(&[cms_der::octet_string(&ukm)]);
            (
                cms_der::sequence(&[cms_der::oid(alg.oid())?, enc_params]),
                ciphertext,
            )
        }
    };

    let mut recipient_infos = Vec::with_capacity(recipients.len());
    for r in recipients {
        recipient_infos.push(build_key_trans_recipient(&cek, r)?);
    }
    cek.zeroize();

    let encrypted_content_info = cms_der::sequence(&[
        cms_der::oid(OID_DATA)?,
        content_enc_alg,
        cms_der::context_primitive(0, &ciphertext),
    ]);

    let enveloped = cms_der::sequence(&[
        cms_der::integer_u8(0),
        cms_der::set(recipient_infos),
        encrypted_content_info,
    ]);
    Ok(cms_der::sequence(&[
        cms_der::oid(OID_ENVELOPED_DATA)?,
        cms_der::explicit0(&enveloped),
    ]))
}

/// Decrypt CMS EnvelopedData ContentInfo with a matching private key.
pub fn decrypt(cms_der_bytes: &[u8], key: &DecryptKey) -> Result<Vec<u8>> {
    let (alg, iv_or_ukm, ciphertext, recipients) = parse_enveloped(cms_der_bytes)?;
    let mut last_err: Option<anyhow::Error> = None;
    for ri in &recipients {
        match try_unwrap_recipient(ri, key) {
            Ok(mut cek) => {
                let plaintext = decrypt_content(alg, &cek, &iv_or_ukm, &ciphertext)?;
                cek.zeroize();
                return Ok(plaintext);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no RecipientInfo matched decrypt key")))
}

fn decrypt_content(alg: ContentAlg, cek: &[u8; 32], params: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    match alg {
        ContentAlg::Gost28147Cfb => {
            if params.len() != 8 {
                bail!("GOST 28147 IV must be 8 bytes");
            }
            let mut iv = [0u8; 8];
            iv.copy_from_slice(params);
            Ok(gost28147::decrypt_cfb(cek, &iv, ciphertext, &gost28147::SBOX_TC26_Z))
        }
        ContentAlg::MagmaCtrAcpkm => {
            if params.len() < 4 {
                bail!("Magma UKM too short");
            }
            let mut iv = [0u8; 4];
            iv.copy_from_slice(&params[..4]);
            gost3412::magma_ctr_acpkm(cek, &iv, ciphertext, gost3412::CMS_MAGMA_SECTION)
        }
        ContentAlg::KuznyechikCtrAcpkm => {
            if params.len() < 8 {
                bail!("Kuznyechik UKM too short");
            }
            let mut iv = [0u8; 8];
            iv.copy_from_slice(&params[..8]);
            gost3412::kuznyechik_ctr_acpkm(cek, &iv, ciphertext, gost3412::CMS_KUZNYECHIK_SECTION)
        }
    }
}

fn build_key_trans_recipient(cek: &[u8; 32], recipient: &RecipientKey) -> Result<Vec<u8>> {
    let identity = x509::identity(&recipient.cert_der)?;
    let curve = curves::by_oid(&identity.curve_oid)
        .with_context(|| format!("unsupported recipient curve {}", identity.curve_oid))?;
    let (vko_oid, pub_oid) = if curve.bytes >= 64 {
        (OID_VKO_512, OID_PUB_512)
    } else {
        (OID_VKO_256, OID_PUB_256)
    };

    let mut ukm = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut ukm);
    if ukm.iter().all(|&b| b == 0) {
        ukm[7] = 1;
    }

    let mut eph_le = gost3410::generate_private_le(&curve);
    let eph_d = BigUint::from_bytes_le(&eph_le);
    let eph_pub = curves::public_key(&curve, &eph_d)?;
    let mut eph_x = eph_pub.x.to_bytes_le();
    let mut eph_y = eph_pub.y.to_bytes_le();
    pad_le(&mut eph_x, curve.bytes);
    pad_le(&mut eph_y, curve.bytes);

    let recip_point = curves::Point {
        x: BigUint::from_bytes_le(&identity.public_x_le),
        y: BigUint::from_bytes_le(&identity.public_y_le),
    };
    let mut kek = vko(&curve, &eph_d, &recip_point, &ukm)?;
    let (cek_enc, cek_mac) =
        gost28147::wrap_cek_none(&kek, &ukm, cek, &gost28147::SBOX_TC26_Z)?;
    kek.zeroize();
    eph_le.zeroize();

    let encrypted_key = cms_der::sequence(&[
        cms_der::octet_string(&cek_enc),
        cms_der::octet_string(&cek_mac),
    ]);

    let spki = subject_public_key_info(pub_oid, &curve.oid, &eph_x, &eph_y)?;
    let tp_body = concat_bytes(&[
        cms_der::oid(OID_GOST28147_PARAM_Z)?,
        cms_der::context_primitive(0, &spki),
        cms_der::context_constructed(1, &cms_der::octet_string(&ukm)),
    ]);
    let transport_params = cms_der::tlv(0xA0, &tp_body);
    let key_transport = cms_der::sequence(&[encrypted_key, transport_params]);

    let rid = cms_der::sequence(&[identity.issuer_der.clone(), identity.serial_der.clone()]);
    let key_enc_alg = cms_der::sequence(&[
        cms_der::oid(vko_oid)?,
        cms_der::sequence(&[
            cms_der::oid(OID_NONE_KEY_WRAP)?,
            cms_der::sequence(&[cms_der::oid(OID_GOST28147_PARAM_Z)?]),
        ]),
    ]);

    Ok(cms_der::sequence(&[
        cms_der::integer_u8(0),
        rid,
        key_enc_alg,
        cms_der::octet_string(&key_transport),
    ]))
}

/// VKO GOST R 34.10-2012 (RFC 7836): KEK = Streebog((UKM·d mod q)·Q).
pub fn vko(
    curve: &curves::Curve,
    private_d: &BigUint,
    peer_pub: &curves::Point,
    ukm: &[u8],
) -> Result<[u8; 32]> {
    if ukm.is_empty() || ukm.iter().all(|&b| b == 0) {
        bail!("UKM must be non-zero");
    }
    let ukm_int = BigUint::from_bytes_be(ukm);
    let scalar = (ukm_int * private_d) % &curve.q;
    if scalar.is_zero() {
        bail!("VKO scalar became zero");
    }
    let point = curves::scalar_mul_point(curve, peer_pub, &scalar)?;
    let mut x = point.x.to_bytes_le();
    let mut y = point.y.to_bytes_le();
    pad_le(&mut x, curve.bytes);
    pad_le(&mut y, curve.bytes);
    let mut coord = Vec::with_capacity(curve.bytes * 2);
    coord.extend_from_slice(&x);
    coord.extend_from_slice(&y);

    let mut out = [0u8; 32];
    if curve.bytes >= 64 {
        let mut h = Streebog512::new();
        h.update(&coord);
        out.copy_from_slice(&h.finalize()[..32]);
    } else {
        let mut h = Streebog256::new();
        h.update(&coord);
        out.copy_from_slice(&h.finalize());
    }
    Ok(out)
}

fn subject_public_key_info(
    pub_oid: &str,
    curve_oid: &str,
    x_le: &[u8],
    y_le: &[u8],
) -> Result<Vec<u8>> {
    let mut key = Vec::with_capacity(x_le.len() + y_le.len());
    key.extend_from_slice(x_le);
    key.extend_from_slice(y_le);
    let alg = cms_der::sequence(&[cms_der::oid(pub_oid)?, cms_der::oid(curve_oid)?]);
    let key_oct = cms_der::octet_string(&key);
    Ok(cms_der::sequence(&[alg, cms_der::bit_string(&key_oct)]))
}

fn pad_le(v: &mut Vec<u8>, len: usize) {
    if v.len() > len {
        v.truncate(len);
    } else {
        v.resize(len, 0);
    }
}

fn concat_bytes(parts: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

fn parse_enveloped(cms: &[u8]) -> Result<(ContentAlg, Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
    let top = der::parse_tlv(cms)?;
    if top.tag != 0x30 {
        bail!("CMS ContentInfo is not SEQUENCE");
    }
    let parts = der::children(top.value)?;
    if parts.len() < 2 {
        bail!("truncated ContentInfo");
    }
    let oid = der::decode_oid(parts[0].value).context("envelopedData OID")?;
    if oid != OID_ENVELOPED_DATA {
        bail!("not envelopedData (got {oid})");
    }
    let wrapped = if parts[1].tag == 0xA0 {
        der::parse_tlv(parts[1].value)?
    } else {
        parts[1]
    };
    if wrapped.tag != 0x30 {
        bail!("EnvelopedData is not SEQUENCE");
    }
    let ed = der::children(wrapped.value)?;
    if ed.len() < 3 {
        bail!("truncated EnvelopedData");
    }
    if ed[1].tag != 0x31 {
        bail!("RecipientInfos is not SET");
    }
    let recipients = extract_set_elements(ed[1].value)?;
    let (alg, params, ciphertext) = parse_encrypted_content_tlv(&ed[2])?;
    Ok((alg, params, ciphertext, recipients))
}

fn extract_set_elements(set_value: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = set_value;
    while !rest.is_empty() {
        let t = der::parse_tlv(rest)?;
        out.push(rest[..t.total_len].to_vec());
        rest = &rest[t.total_len..];
    }
    Ok(out)
}

fn parse_encrypted_content_tlv(eci: &der::Tlv<'_>) -> Result<(ContentAlg, Vec<u8>, Vec<u8>)> {
    let parts = der::children(eci.value)?;
    if parts.len() < 3 {
        bail!("truncated EncryptedContentInfo");
    }
    let alg_parts = der::children(parts[1].value)?;
    if alg_parts.is_empty() {
        bail!("missing contentEncryptionAlgorithm");
    }
    let alg_oid = der::decode_oid(alg_parts[0].value).context("contentEncryptionAlgorithm OID")?;
    let alg = ContentAlg::from_oid(&alg_oid)?;
    if alg_parts.len() < 2 {
        bail!("missing contentEncryptionAlgorithm parameters");
    }
    let params_seq = der::children(alg_parts[1].value)?;
    if params_seq.is_empty() || params_seq[0].tag != 0x04 {
        bail!("missing OCTET STRING in encryption parameters");
    }
    let params = params_seq[0].value.to_vec();
    match alg {
        ContentAlg::Gost28147Cfb => {
            if params.len() != 8 {
                bail!("GOST 28147 IV must be 8 bytes");
            }
        }
        ContentAlg::MagmaCtrAcpkm => {
            if params.len() < 4 {
                bail!("Magma UKM must be at least 4 bytes");
            }
        }
        ContentAlg::KuznyechikCtrAcpkm => {
            if params.len() < 8 {
                bail!("Kuznyechik UKM must be at least 8 bytes");
            }
        }
    }
    let enc = &parts[2];
    let ciphertext = match enc.tag {
        0x80 => enc.value.to_vec(),
        0xA0 => {
            let inner = der::parse_tlv(enc.value)?;
            if inner.tag != 0x04 {
                bail!("encryptedContent EXPLICIT is not OCTET STRING");
            }
            inner.value.to_vec()
        }
        0x04 => enc.value.to_vec(),
        _ => bail!("missing encryptedContent"),
    };
    Ok((alg, params, ciphertext))
}

fn try_unwrap_recipient(ri_der: &[u8], key: &DecryptKey) -> Result<[u8; 32]> {
    let ri = der::parse_tlv(ri_der)?;
    let parts = der::children(ri.value)?;
    if parts.len() < 4 {
        bail!("truncated RecipientInfo");
    }
    let rid_parts = der::children(parts[1].value)?;
    if rid_parts.len() < 2 {
        bail!("bad rid");
    }
    let issuer_der = cms_der::tlv(rid_parts[0].tag, rid_parts[0].value);
    let serial_der = cms_der::tlv(rid_parts[1].tag, rid_parts[1].value);
    if !x509::issuer_serial_matches(&key.cert_der, &issuer_der, &serial_der)? {
        bail!("rid mismatch");
    }

    let kt_oct = if parts[3].tag == 0x04 {
        parts[3].value
    } else {
        bail!("encryptedKey is not OCTET STRING");
    };
    let kt = der::parse_tlv(kt_oct)?;
    let kt_parts = der::children(kt.value)?;
    if kt_parts.is_empty() {
        bail!("empty KeyTransport");
    }
    let session = der::children(kt_parts[0].value)?;
    if session.len() < 2 || session[0].tag != 0x04 || session[1].tag != 0x04 {
        bail!("bad sessionEncryptedKey");
    }
    let cek_enc = session[0].value;
    if session[1].value.len() < 4 {
        bail!("short CEK MAC");
    }
    let mut mac = [0u8; 4];
    mac.copy_from_slice(&session[1].value[..4]);

    let mut ukm = [0u8; 8];
    let mut eph_x = Vec::new();
    let mut eph_y = Vec::new();
    if kt_parts.len() > 1 && kt_parts[1].tag == 0xA0 {
        for p in der::children(kt_parts[1].value)? {
            match p.tag {
                0x80 => parse_eph_key(p.value, &key.curve, &mut eph_x, &mut eph_y)?,
                0xA0 => {
                    let inner = der::parse_tlv(p.value)?;
                    if inner.tag == 0x30 {
                        parse_eph_from_spki(
                            &p.value[..inner.total_len],
                            &key.curve,
                            &mut eph_x,
                            &mut eph_y,
                        )?;
                    }
                }
                0xA1 => {
                    let inner = der::parse_tlv(p.value)?;
                    if inner.tag == 0x04 && inner.value.len() >= 8 {
                        ukm.copy_from_slice(&inner.value[..8]);
                    }
                }
                0x30 => {
                    let full = cms_der::tlv(0x30, p.value);
                    parse_eph_from_spki(&full, &key.curve, &mut eph_x, &mut eph_y)?;
                }
                _ => {}
            }
        }
    }
    if eph_x.is_empty() || eph_y.is_empty() {
        bail!("ephemeral public key missing");
    }
    if ukm.iter().all(|&b| b == 0) {
        bail!("UKM missing");
    }

    let d = BigUint::from_bytes_le(&key.private_le);
    let eph = curves::Point {
        x: BigUint::from_bytes_le(&eph_x),
        y: BigUint::from_bytes_le(&eph_y),
    };
    let mut kek = vko(&key.curve, &d, &eph, &ukm)?;
    let cek = gost28147::unwrap_cek_none(&kek, &ukm, cek_enc, &mac, &gost28147::SBOX_TC26_Z)?;
    kek.zeroize();
    Ok(cek)
}

fn parse_eph_from_spki(
    spki: &[u8],
    curve: &curves::Curve,
    x: &mut Vec<u8>,
    y: &mut Vec<u8>,
) -> Result<()> {
    let top = der::parse_tlv(spki)?;
    let parts = der::children(top.value)?;
    if parts.len() < 2 {
        bail!("bad SPKI");
    }
    let bits = if parts[1].tag == 0x03 {
        if parts[1].value.is_empty() {
            bail!("empty BIT STRING");
        }
        &parts[1].value[1..]
    } else {
        parts[1].value
    };
    parse_eph_key(bits, curve, x, y)
}

fn parse_eph_key(
    value: &[u8],
    curve: &curves::Curve,
    x: &mut Vec<u8>,
    y: &mut Vec<u8>,
) -> Result<()> {
    let payload = if let Ok(inner) = der::parse_tlv(value) {
        if inner.tag == 0x04 {
            inner.value
        } else if inner.tag == 0x30 {
            return parse_eph_from_spki(value, curve, x, y);
        } else {
            value
        }
    } else {
        value
    };
    if payload.len() < curve.bytes * 2 {
        bail!("short ephemeral key");
    }
    *x = payload[..curve.bytes].to_vec();
    *y = payload[curve.bytes..curve.bytes * 2].to_vec();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cert(curve: &curves::Curve, x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut xy = x.to_vec();
        xy.extend_from_slice(y);
        let public_key_alg = cms_der::sequence(&[
            cms_der::oid(OID_PUB_256).unwrap(),
            cms_der::sequence(&[
                cms_der::oid(curve.oid).unwrap(),
                cms_der::oid("1.2.643.7.1.1.2.2").unwrap(),
            ]),
        ]);
        let spki = cms_der::sequence(&[
            public_key_alg,
            cms_der::bit_string(&cms_der::octet_string(&xy)),
        ]);
        let empty_name = cms_der::sequence(&[]);
        let tbs = cms_der::sequence(&[
            cms_der::explicit0(&cms_der::integer_u8(2)),
            cms_der::integer_u8(1),
            cms_der::algorithm_identifier(OID_PUB_256).unwrap(),
            empty_name.clone(),
            cms_der::sequence(&[]),
            empty_name,
            spki,
        ]);
        cms_der::sequence(&[
            tbs,
            cms_der::algorithm_identifier(OID_PUB_256).unwrap(),
            cms_der::bit_string(&[0u8; 64]),
        ])
    }

    #[test]
    fn vko_is_symmetric() {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let d_a = BigUint::from_bytes_le(&gost3410::generate_private_le(&curve));
        let d_b = BigUint::from_bytes_le(&gost3410::generate_private_le(&curve));
        let q_a = curves::public_key(&curve, &d_a).unwrap();
        let q_b = curves::public_key(&curve, &d_b).unwrap();
        let ukm = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let k1 = vko(&curve, &d_a, &q_b, &ukm).unwrap();
        let k2 = vko(&curve, &d_b, &q_a, &ukm).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn wrap_unwrap_cek() {
        let kek = [0x11u8; 32];
        let ukm = [0x22u8; 8];
        let cek = [0x33u8; 32];
        let (enc, mac) =
            gost28147::wrap_cek_none(&kek, &ukm, &cek, &gost28147::SBOX_TC26_Z).unwrap();
        let back =
            gost28147::unwrap_cek_none(&kek, &ukm, &enc, &mac, &gost28147::SBOX_TC26_Z).unwrap();
        assert_eq!(back, cek);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        roundtrip_alg(ContentAlg::Gost28147Cfb);
    }

    #[test]
    fn encrypt_decrypt_magma() {
        roundtrip_alg(ContentAlg::MagmaCtrAcpkm);
    }

    #[test]
    fn encrypt_decrypt_kuznyechik() {
        roundtrip_alg(ContentAlg::KuznyechikCtrAcpkm);
    }

    fn roundtrip_alg(alg: ContentAlg) {
        let curve = curves::by_oid("1.2.643.7.1.2.1.1.2").unwrap();
        let private_le = gost3410::generate_private_le(&curve);
        let d = BigUint::from_bytes_le(&private_le);
        let pubp = curves::public_key(&curve, &d).unwrap();
        let mut x = pubp.x.to_bytes_le();
        let mut y = pubp.y.to_bytes_le();
        pad_le(&mut x, curve.bytes);
        pad_le(&mut y, curve.bytes);
        let cert = fake_cert(&curve, &x, &y);
        x509::identity(&cert).expect("fake cert identity");

        let plain = b"jex enveloped gost roundtrip!";
        let cms = encrypt_with(plain, &[RecipientKey { cert_der: cert.clone() }], alg).unwrap();
        let pt = decrypt(
            &cms,
            &DecryptKey {
                private_le,
                curve,
                cert_der: cert,
            },
        )
        .unwrap();
        assert_eq!(pt, plain, "alg={}", alg.as_str());
    }
}
