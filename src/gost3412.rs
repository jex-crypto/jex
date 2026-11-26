// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! GOST R 34.12-2015 Magma / Kuznyechik and CTR-ACPKM (Р 1323565.1.017).
//!
//! Magma uses GOST 28147-89 ParamSet Z with Magma byte-order transforms (pygost-
//! compatible). CTR-ACPKM CMS section sizes follow Р 1323565.1.025-2019.

use crate::gost28147;
use anyhow::{bail, Result};
use std::sync::OnceLock;

/// CMS section sizes (Р 1323565.1.025-2019).
pub const CMS_MAGMA_SECTION: usize = 8 * 1024;
pub const CMS_KUZNYECHIK_SECTION: usize = 256 * 1024;

/// Magma encrypt one 8-byte block (GOST R 34.12-2015).
pub fn magma_encrypt_block(key: &[u8; 32], block: &[u8; 8]) -> [u8; 8] {
    let mut k28147 = [0u8; 32];
    for i in 0..8 {
        let w = &key[i * 4..i * 4 + 4];
        k28147[i * 4..i * 4 + 4].copy_from_slice(&[w[3], w[2], w[1], w[0]]);
    }
    let mut rev = *block;
    rev.reverse();
    let mut out = gost28147::encrypt_block(&k28147, &rev, &gost28147::SBOX_TC26_Z);
    out.reverse();
    out
}

/// Kuznyechik (GOST R 34.12-2015).
pub struct Kuznyechik {
    ks: [[u8; 16]; 10],
}

impl Kuznyechik {
    pub fn new(key: &[u8; 32]) -> Self {
        let c = round_constants();
        let mut kr0 = [0u8; 16];
        let mut kr1 = [0u8; 16];
        kr0.copy_from_slice(&key[..16]);
        kr1.copy_from_slice(&key[16..]);
        let mut ks = [[0u8; 16]; 10];
        ks[0] = kr0;
        ks[1] = kr1;
        let mut idx = 2;
        for i in 0..4 {
            for j in 0..8 {
                let mut t = [0u8; 16];
                for k in 0..16 {
                    t[k] = c[8 * i + j][k] ^ kr0[k];
                }
                t = lp(t);
                let next0 = xor16(&t, &kr1);
                kr1 = kr0;
                kr0 = next0;
            }
            ks[idx] = kr0;
            ks[idx + 1] = kr1;
            idx += 2;
        }
        Self { ks }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut blk = *block;
        for i in 0..9 {
            blk = lp(xor16(&self.ks[i], &blk));
        }
        xor16(&self.ks[9], &blk)
    }
}

/// ACPKM(K) = E_K(D₁)‖… ; D starts at 0x80.
fn acpkm(block_size: usize, encrypt: &dyn Fn(&[u8]) -> Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut off = 0;
    let mut d = 0x80usize;
    while off < 32 {
        let mut plain = vec![0u8; block_size];
        for i in 0..block_size {
            plain[i] = (d + i) as u8;
        }
        let enc = encrypt(&plain);
        out[off..off + block_size].copy_from_slice(&enc[..block_size]);
        off += block_size;
        d += block_size;
    }
    out
}

/// Magma CTR-ACPKM (encrypt ≡ decrypt). `iv` is 4 bytes.
pub fn magma_ctr_acpkm(key: &[u8; 32], iv: &[u8; 4], data: &[u8], section_size: usize) -> Result<Vec<u8>> {
    if section_size == 0 || section_size % 8 != 0 {
        bail!("invalid Magma ACPKM section size");
    }
    let section_blocks = section_size / 8;
    let half = 4usize;
    let needed = data.len().div_ceil(8);
    let mut key = *key;
    let mut stream = Vec::with_capacity(needed * 8);
    let mut ctr_value = 0u64;
    for _ in 0..needed {
        if ctr_value != 0 && (ctr_value as usize) % section_blocks == 0 {
            let cur = key;
            let enc = |b: &[u8]| {
                let mut blk = [0u8; 8];
                blk.copy_from_slice(&b[..8]);
                magma_encrypt_block(&cur, &blk).to_vec()
            };
            key = acpkm(8, &enc);
        }
        let mut ctr_block = [0u8; 8];
        ctr_block[..half].copy_from_slice(iv);
        for i in 0..half {
            ctr_block[half + i] = ((ctr_value >> (8 * (half - 1 - i))) & 0xff) as u8;
        }
        stream.extend_from_slice(&magma_encrypt_block(&key, &ctr_block));
        ctr_value = ctr_value.wrapping_add(1);
    }
    let mut out = data.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= stream[i];
    }
    Ok(out)
}

/// Kuznyechik CTR-ACPKM (encrypt ≡ decrypt). `iv` is 8 bytes.
pub fn kuznyechik_ctr_acpkm(
    key: &[u8; 32],
    iv: &[u8; 8],
    data: &[u8],
    section_size: usize,
) -> Result<Vec<u8>> {
    if section_size == 0 || section_size % 16 != 0 {
        bail!("invalid Kuznyechik ACPKM section size");
    }
    let section_blocks = section_size / 16;
    let half = 8usize;
    let needed = data.len().div_ceil(16);
    let mut key = *key;
    let mut cipher = Kuznyechik::new(&key);
    let mut stream = Vec::with_capacity(needed * 16);
    let mut ctr_value = 0u128;
    for _ in 0..needed {
        if ctr_value != 0 && (ctr_value as usize) % section_blocks == 0 {
            let enc = |b: &[u8]| {
                let mut blk = [0u8; 16];
                blk.copy_from_slice(&b[..16]);
                cipher.encrypt_block(&blk).to_vec()
            };
            let new_key = acpkm(16, &enc);
            key = new_key;
            cipher = Kuznyechik::new(&key);
        }
        let mut ctr_block = [0u8; 16];
        ctr_block[..half].copy_from_slice(iv);
        for i in 0..half {
            ctr_block[half + i] = ((ctr_value >> (8 * (half - 1 - i))) & 0xff) as u8;
        }
        stream.extend_from_slice(&cipher.encrypt_block(&ctr_block));
        ctr_value = ctr_value.wrapping_add(1);
    }
    let mut out = data.to_vec();
    for (i, b) in out.iter_mut().enumerate() {
        *b ^= stream[i];
    }
    Ok(out)
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

fn lp(blk: [u8; 16]) -> [u8; 16] {
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = PI[blk[i] as usize];
    }
    l_transform(t)
}

fn l_transform(mut blk: [u8; 16]) -> [u8; 16] {
    for _ in 0..16 {
        let mut t = blk[15];
        for i in (0..15).rev() {
            blk[i + 1] = blk[i];
            t ^= gf(blk[i] as u32, LC[i] as u32);
        }
        blk[0] = t;
    }
    blk
}

fn gf(mut a: u32, mut b: u32) -> u8 {
    let mut c = 0u32;
    while b != 0 {
        if b & 1 != 0 {
            c ^= a;
        }
        if a & 0x80 != 0 {
            a = (a << 1) ^ 0x1C3;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    (c & 0xff) as u8
}

fn round_constants() -> &'static [[u8; 16]; 32] {
    static CELL: OnceLock<[[u8; 16]; 32]> = OnceLock::new();
    CELL.get_or_init(|| {
        let mut c = [[0u8; 16]; 32];
        for x in 1..=32 {
            let mut y = [0u8; 16];
            y[15] = x as u8;
            c[x - 1] = l_transform(y);
        }
        c
    })
}

const LC: [u8; 16] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147,
    46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28,
    60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8,
    12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145,
    120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189,
    13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
    222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26,
    184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213,
    149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131,
    73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91,
    203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194,
    57, 75, 99, 182,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s.replace([' ', '\n'], "")).unwrap()
    }

    #[test]
    fn magma_acpkm_key_vector() {
        let key: [u8; 32] = hex("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
            .try_into()
            .unwrap();
        let enc = |b: &[u8]| {
            let mut blk = [0u8; 8];
            blk.copy_from_slice(&b[..8]);
            magma_encrypt_block(&key, &blk).to_vec()
        };
        let out = acpkm(8, &enc);
        assert_eq!(
            out.as_slice(),
            hex("863EA017842C3D372B18A85A28E2317D74BEFC107720DE0C9E8AB974ABD00CA0").as_slice()
        );
    }

    #[test]
    fn kuznyechik_acpkm_key_vector() {
        let key: [u8; 32] = hex("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
            .try_into()
            .unwrap();
        let c = Kuznyechik::new(&key);
        let enc = |b: &[u8]| {
            let mut blk = [0u8; 16];
            blk.copy_from_slice(&b[..16]);
            c.encrypt_block(&blk).to_vec()
        };
        let out = acpkm(16, &enc);
        assert_eq!(
            out.as_slice(),
            hex("2666ED40AE687811745CA0B448F57A7B390ADB5780307E8E9659AC403AE60C60").as_slice()
        );
    }

    #[test]
    fn magma_ctr_acpkm_vector() {
        let key: [u8; 32] = hex("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
            .try_into()
            .unwrap();
        let iv: [u8; 4] = hex("12345678").try_into().unwrap();
        let pt = hex(
            "1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A\
             112233445566778899AABBCCEEFF0A002233445566778899",
        );
        let ct = hex(
            "2AB81DEEEB1E4CAB68E104C4BD6B94EAC72C67AF6C2E5B6B0EAFB61770F1B32E\
             A1AE71149EED1382ABD467180672EC6F84A2F15B3FCA72C1",
        );
        let out = magma_ctr_acpkm(&key, &iv, &pt, 8 * 2).unwrap();
        assert_eq!(out, ct);
        let back = magma_ctr_acpkm(&key, &iv, &ct, 8 * 2).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn kuznyechik_ctr_acpkm_vector() {
        let key: [u8; 32] = hex("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
            .try_into()
            .unwrap();
        let iv: [u8; 8] = hex("1234567890ABCEF0").try_into().unwrap();
        let pt = hex(
            "1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A\
             112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011\
             33445566778899AABBCCEEFF0A001122445566778899AABBCCEEFF0A00112233\
             5566778899AABBCCEEFF0A0011223344",
        );
        let ct = hex(
            "F195D8BEC10ED1DBD57B5FA240BDA1B885EEE733F6A13E5DF33CE4B33C45DEE4\
             4BCEEB8F646F4C55001706275E85E800587C4DF568D094393E4834AFD0805046\
             CF30F57686AEECE11CFC6C316B8A896EDFFD07EC813636460C4F3B743423163E\
             6409A9C282FAC8D469D221E7FBD6DE5D",
        );
        let out = kuznyechik_ctr_acpkm(&key, &iv, &pt, 16 * 2).unwrap();
        assert_eq!(out, ct);
        let back = kuznyechik_ctr_acpkm(&key, &iv, &ct, 16 * 2).unwrap();
        assert_eq!(back, pt);
    }
}
