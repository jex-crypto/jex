// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use anyhow::{bail, Result};

pub type Sbox = [[u8; 16]; 8];

pub const SBOX_TC26_Z: Sbox = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
];

const SEQ_ENCRYPT: [usize; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
];

const SEQ_DECRYPT: [usize; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0, 7, 6, 5, 4, 3, 2, 1, 0,
];

/// GOST 28147-89 MAC (IMIT) uses 16 rounds: K0..K7 twice.
const SEQ_MAC: [usize; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7];

fn substitute(s: &Sbox, x: u32) -> u32 {
    let mut out = 0u32;
    for (i, row) in s.iter().enumerate() {
        let nibble = ((x >> (i * 4)) & 0x0f) as usize;
        out |= (row[nibble] as u32) << (i * 4);
    }
    out
}

fn block_to_words(b: &[u8; 8]) -> (u32, u32) {
    (
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u32::from_le_bytes(b[4..8].try_into().unwrap()),
    )
}

fn words_to_block(n1: u32, n2: u32) -> [u8; 8] {
    // GOST 28147's Feistel operation returns swapped halves.
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&n2.to_le_bytes());
    out[4..8].copy_from_slice(&n1.to_le_bytes());
    out
}

fn key_words(key: &[u8; 32]) -> [u32; 8] {
    let mut kw = [0u32; 8];
    for i in 0..8 {
        kw[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    kw
}

fn crypt_block(key: &[u8; 32], block: &[u8; 8], sbox: &Sbox, schedule: &[usize]) -> [u8; 8] {
    let kw = key_words(key);
    let (mut n1, mut n2) = block_to_words(block);
    for &idx in schedule {
        let t = n1.wrapping_add(kw[idx]);
        let t = substitute(sbox, t).rotate_left(11) ^ n2;
        n2 = n1;
        n1 = t;
    }
    words_to_block(n1, n2)
}

pub(crate) fn decrypt_block(key: &[u8; 32], block: &[u8; 8], sbox: &Sbox) -> [u8; 8] {
    crypt_block(key, block, sbox, &SEQ_DECRYPT)
}

pub(crate) fn encrypt_block(key: &[u8; 32], block: &[u8; 8], sbox: &Sbox) -> [u8; 8] {
    crypt_block(key, block, sbox, &SEQ_ENCRYPT)
}

/// GOST 28147-89 CFB (CryptoPro / «гаммирование с обратной связью»), 64-bit feedback.
pub fn encrypt_cfb(key: &[u8; 32], iv: &[u8; 8], data: &[u8], sbox: &Sbox) -> Vec<u8> {
    cfb(key, iv, data, sbox, true)
}

pub fn decrypt_cfb(key: &[u8; 32], iv: &[u8; 8], data: &[u8], sbox: &Sbox) -> Vec<u8> {
    cfb(key, iv, data, sbox, false)
}

fn cfb(key: &[u8; 32], iv: &[u8; 8], data: &[u8], sbox: &Sbox, encrypt: bool) -> Vec<u8> {
    let mut gamma_in = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(8) {
        let gamma = encrypt_block(key, &gamma_in, sbox);
        let mut block_out = [0u8; 8];
        for (i, b) in chunk.iter().enumerate() {
            block_out[i] = b ^ gamma[i];
            out.push(block_out[i]);
        }
        // Feedback is ciphertext (encrypt) or input ciphertext (decrypt).
        if encrypt {
            gamma_in = block_out;
            if chunk.len() < 8 {
                gamma_in[chunk.len()..].copy_from_slice(&gamma[chunk.len()..]);
            }
        } else {
            let mut ct = [0u8; 8];
            ct[..chunk.len()].copy_from_slice(chunk);
            if chunk.len() < 8 {
                // partial: remaining gamma bits unused for feedback in classic CFB;
                // CryptoPro pads by keeping previous gamma bytes in the register.
                ct[chunk.len()..].copy_from_slice(&gamma_in[chunk.len()..]);
            }
            gamma_in = ct;
        }
    }
    out
}

fn ecb(key: &[u8; 32], data: &[u8], sbox: &Sbox, encrypt: bool) -> Result<Vec<u8>> {
    if data.is_empty() || data.len() % 8 != 0 {
        bail!("GOST 28147 ECB data must be a non-empty multiple of 8 bytes");
    }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let block: [u8; 8] = chunk.try_into().unwrap();
        let r = if encrypt {
            encrypt_block(key, &block, sbox)
        } else {
            decrypt_block(key, &block, sbox)
        };
        out.extend_from_slice(&r);
    }
    Ok(out)
}

pub fn decrypt_ecb(key: &[u8; 32], data: &[u8], sbox: &Sbox) -> Result<Vec<u8>> {
    ecb(key, data, sbox, false)
}

pub fn encrypt_ecb(key: &[u8; 32], data: &[u8], sbox: &Sbox) -> Result<Vec<u8>> {
    ecb(key, data, sbox, true)
}

/// CryptoPro classic-container `masks.key` integrity tag: GOST 28147-89 MAC
/// with key = mask, data = salt; first 4 bytes of the 8-byte tag.
///
/// Matches pygost/`ckey` MAC (SEQ_MAC, zero IV, pad with zeros).
pub fn mac_imit4(key: &[u8; 32], data: &[u8], sbox: &Sbox) -> [u8; 4] {
    mac_imit4_iv(key, &[0u8; 8], data, sbox)
}

/// GOST 28147-89 MAC (IMIT) with explicit IV — used by CryptoPro key wrap (RFC 4357).
pub fn mac_imit4_iv(key: &[u8; 32], iv: &[u8; 8], data: &[u8], sbox: &Sbox) -> [u8; 4] {
    let mut padded = data.to_vec();
    let rem = padded.len() % 8;
    if rem != 0 {
        padded.resize(padded.len() + (8 - rem), 0);
    } else if padded.is_empty() {
        padded.resize(8, 0);
    }

    let kw = key_words(key);
    let (mut prev_n1, mut prev_n2) = block_to_words(iv);
    // pygost: after loading IV as block2ns, reverse once like zero-IV path start.
    // CryptoPro wrap uses IV directly as the initial gamma register (ns order).
    std::mem::swap(&mut prev_n1, &mut prev_n2);
    for chunk in padded.chunks_exact(8) {
        let ns_block = words_to_block(prev_n1, prev_n2);
        let mut xored = [0u8; 8];
        for i in 0..8 {
            xored[i] = chunk[i] ^ ns_block[i];
        }
        let (mut n1, mut n2) = block_to_words(&xored);
        for &idx in &SEQ_MAC {
            let t = n1.wrapping_add(kw[idx]);
            let t = substitute(sbox, t).rotate_left(11) ^ n2;
            n2 = n1;
            n1 = t;
        }
        prev_n1 = n2;
        prev_n2 = n1;
    }
    let tag = words_to_block(prev_n1, prev_n2);
    [tag[0], tag[1], tag[2], tag[3]]
}

/// CryptoPro None-KeyWrap (RFC 4357 §6.1 / ТК26): CEK_ENC || CEK_MAC (no UKM prefix in blob).
pub fn wrap_cek_none(kek: &[u8; 32], ukm: &[u8; 8], cek: &[u8; 32], sbox: &Sbox) -> Result<(Vec<u8>, [u8; 4])> {
    let mac = mac_imit4_iv(kek, ukm, cek, sbox);
    let enc = encrypt_ecb(kek, cek, sbox)?;
    Ok((enc, mac))
}

pub fn unwrap_cek_none(kek: &[u8; 32], ukm: &[u8; 8], cek_enc: &[u8], mac: &[u8; 4], sbox: &Sbox) -> Result<[u8; 32]> {
    if cek_enc.len() != 32 {
        bail!("CEK_ENC must be 32 bytes");
    }
    let cek_vec = decrypt_ecb(kek, cek_enc, sbox)?;
    let mut cek = [0u8; 32];
    cek.copy_from_slice(&cek_vec);
    let expect = mac_imit4_iv(kek, ukm, &cek, sbox);
    if expect != *mac {
        bail!("CEK MAC mismatch");
    }
    Ok(cek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [0x11u8; 32];
        let pt = b"0123456789abcdef";
        let ct = encrypt_ecb(&key, pt, &SBOX_TC26_Z).unwrap();
        assert_ne!(ct, pt);
        let back = decrypt_ecb(&key, &ct, &SBOX_TC26_Z).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn masks_mac_matches_synthetic_sample() {
        // Synthetic masks.key layout: MAC(key=mask, data=salt)[:4]
        let mask = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let salt = hex::decode("a0a1a2a3a4a5a6a7a8a9aaab").unwrap();
        let expected = hex::decode("191d94a9").unwrap();
        let mut key = [0u8; 32];
        key.copy_from_slice(&mask);
        let tag = mac_imit4(&key, &salt, &SBOX_TC26_Z);
        assert_eq!(tag.as_slice(), expected.as_slice());
    }
}
