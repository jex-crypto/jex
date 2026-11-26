// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use streebog::{Digest, Streebog256};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 32] = b"DENEFH028.760246785.IUEFHWUIO.EF";

fn hash256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Streebog256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn widen_pin(pin: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; pin.len() * 4];
    for (i, &b) in pin.iter().enumerate() {
        out[i * 4] = b;
    }
    out
}

fn xor_pad(src: &[u8; 64], value: u8) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = src[i] ^ value;
    }
    out
}

/// CryptoPro classic-container password derivation used by GOST R 34.10-2012
/// containers. This intentionally reproduces the historical construction,
/// rather than replacing it with PBKDF2/HMAC.
pub fn derive_2012(pin: &[u8], salt: &[u8]) -> [u8; 32] {
    let pin4 = Zeroizing::new(widen_pin(pin));
    let hash_result = if pin4.is_empty() {
        hash256(&[salt])
    } else {
        hash256(&[salt, &pin4])
    };

    let mut hash_result = Zeroizing::new(hash_result);
    let mut current = Zeroizing::new([0u8; 64]);
    current[..32].copy_from_slice(MAGIC);

    let rounds = if pin.is_empty() { 2 } else { 2000 };
    for _ in 0..rounds {
        let mut p36 = xor_pad(&current, 0x36);
        let mut p5c = xor_pad(&current, 0x5c);
        let mut next = hash256(&[&p36, &hash_result[..], &p5c, &hash_result[..]]);
        current.fill(0);
        current[..32].copy_from_slice(&next);
        p36.zeroize();
        p5c.zeroize();
        next.zeroize();
    }
    hash_result.zeroize();

    let mut p36 = xor_pad(&current, 0x36);
    let mut p5c = xor_pad(&current, 0x5c);
    let mut inner = if pin4.is_empty() {
        hash256(&[&p36[..32], salt, &p5c[..32]])
    } else {
        hash256(&[&p36[..32], salt, &p5c[..32], &pin4])
    };
    p36.zeroize();
    p5c.zeroize();
    let key = hash256(&[&inner]);
    inner.zeroize();
    key
}
