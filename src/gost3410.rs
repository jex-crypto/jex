// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::curves::{self, Curve, Point};
use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

/// Sign an already-computed GOST R 34.11 digest.
///
/// Input private scalar: little-endian, matching CryptoPro container storage.
/// Input digest: conventional GOST digest byte string, interpreted as a
/// little-endian integer by interoperable GOST implementations (CryptoPro/gost-engine convention).
/// Output: CMS/RFC 9215 octet representation S || R, each fixed-width BE.
pub fn sign_digest(curve: &Curve, private_le: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
    // num-bigint cannot wipe its limbs; only byte buffers are zeroized.
    let d = BigUint::from_bytes_le(private_le) % &curve.q;
    if d.is_zero() {
        bail!("zero GOST private scalar");
    }
    let mut e = BigUint::from_bytes_le(digest) % &curve.q;
    if e.is_zero() {
        e = BigUint::one();
    }

    let mut rng = OsRng;
    loop {
        let k = random_nonzero_below(&curve.q, curve.bytes, &mut rng);
        let c = curves::scalar_mul_generator(curve, &k)?;
        let r = &c.x % &curve.q;
        if r.is_zero() {
            continue;
        }
        let s = ((&r * &d) + (&k * &e)) % &curve.q;
        if s.is_zero() {
            continue;
        }
        let mut out = be_fixed(&s, curve.bytes);
        out.extend_from_slice(&be_fixed(&r, curve.bytes));
        return Ok(out);
    }
}

pub fn verify_digest(
    curve: &Curve,
    public_x_le: &[u8],
    public_y_le: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<bool> {
    if signature.len() != curve.bytes * 2
        || public_x_le.len() != curve.bytes
        || public_y_le.len() != curve.bytes
    {
        return Ok(false);
    }
    let s = BigUint::from_bytes_be(&signature[..curve.bytes]);
    let r = BigUint::from_bytes_be(&signature[curve.bytes..]);
    if r.is_zero() || s.is_zero() || &r >= &curve.q || &s >= &curve.q {
        return Ok(false);
    }
    let mut e = BigUint::from_bytes_le(digest) % &curve.q;
    if e.is_zero() {
        e = BigUint::one();
    }
    let v = e.modpow(&(&curve.q - BigUint::from(2u8)), &curve.q);
    let z1 = (&s * &v) % &curve.q;
    let rv = (&r * &v) % &curve.q;
    let z2 = if rv.is_zero() {
        BigUint::zero()
    } else {
        &curve.q - rv
    };

    let p1 = curves::scalar_mul_generator(curve, &z1)?;
    let q = Point {
        x: BigUint::from_bytes_le(public_x_le),
        y: BigUint::from_bytes_le(public_y_le),
    };
    let p2 = curves::scalar_mul_point(curve, &q, &z2)?;
    let Some(c) = curves::add_public(curve, Some(p1), Some(p2))? else {
        return Ok(false);
    };
    Ok((&c.x % &curve.q) == r)
}

fn random_nonzero_below(q: &BigUint, width: usize, rng: &mut impl RngCore) -> BigUint {
    // Rejection sampling avoids modulo bias. q is close to 2^(8*width), so
    // expected retries are small for TC26 curves.
    loop {
        let mut buf = Zeroizing::new(vec![0u8; width]);
        rng.fill_bytes(&mut buf);
        let k = BigUint::from_bytes_be(&buf);
        if !k.is_zero() && &k < q {
            return k;
        }
    }
}

/// Generate a random GOST private scalar (little-endian fixed width).
pub fn generate_private_le(curve: &Curve) -> Vec<u8> {
    let mut rng = OsRng;
    let d = random_nonzero_below(&curve.q, curve.bytes, &mut rng);
    curves::le_fixed(&d, curve.bytes)
}

fn be_fixed(v: &BigUint, n: usize) -> Vec<u8> {
    let raw = v.to_bytes_be();
    if raw.len() >= n {
        return raw[raw.len() - n..].to_vec();
    }
    let mut out = vec![0u8; n - raw.len()];
    out.extend_from_slice(&raw);
    out
}
