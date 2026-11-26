// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::curves::{self, Curve, Point};
use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{rngs::OsRng, RngCore};
use streebog::{Digest, Streebog512};
use zeroize::{Zeroize, Zeroizing};

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

    // Hedged nonce: RFC 6979 HMAC_DRBG seeded with d, e and fresh OS entropy
    // (RFC 6979 §3.6 "additional data"). A weak or repeating RNG then degrades
    // to deterministic RFC 6979 instead of reusing k across different digests.
    let mut extra = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(extra.as_mut());
    let mut nonces = NonceGen::new(&curve.q, &d, &e, extra.as_ref());
    loop {
        let k = nonces.next();
        if let Some(sig) = sign_with_k(curve, &d, &e, &k)? {
            return Ok(sig);
        }
    }
}

/// One signing attempt with a given nonce; `None` when r or s is zero.
fn sign_with_k(curve: &Curve, d: &BigUint, e: &BigUint, k: &BigUint) -> Result<Option<Vec<u8>>> {
    let c = curves::scalar_mul_generator(curve, k)?;
    let r = &c.x % &curve.q;
    if r.is_zero() {
        return Ok(None);
    }
    let s = ((&r * d) + (k * e)) % &curve.q;
    if s.is_zero() {
        return Ok(None);
    }
    let mut out = be_fixed(&s, curve.bytes);
    out.extend_from_slice(&be_fixed(&r, curve.bytes));
    Ok(Some(out))
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

/// RFC 6979 §3.2 HMAC_DRBG over HMAC-Streebog-512 (RFC 7836), with optional
/// additional data mixed into the seed (§3.6).
struct NonceGen<'a> {
    q: &'a BigUint,
    qlen: u64,
    rlen: usize,
    k: Zeroizing<[u8; 64]>,
    v: Zeroizing<[u8; 64]>,
}

impl<'a> NonceGen<'a> {
    fn new(q: &'a BigUint, d: &BigUint, e: &BigUint, extra: &[u8]) -> Self {
        let qlen = q.bits();
        let rlen = qlen.div_ceil(8) as usize;
        let x = Zeroizing::new(be_fixed(d, rlen));
        let h1 = be_fixed(&(e % q), rlen);
        let mut g = NonceGen {
            q,
            qlen,
            rlen,
            k: Zeroizing::new([0u8; 64]),
            v: Zeroizing::new([1u8; 64]),
        };
        for sep in [0u8, 1u8] {
            let k = hmac_streebog512(
                g.k.as_ref(),
                &[g.v.as_ref(), &[sep], &x, &h1, extra],
            );
            *g.k = *k;
            g.rehash_v();
        }
        g
    }

    fn rehash_v(&mut self) {
        let v = hmac_streebog512(self.k.as_ref(), &[self.v.as_ref()]);
        *self.v = *v;
    }

    /// Next candidate k in [1, q-1].
    fn next(&mut self) -> BigUint {
        loop {
            // rlen <= 64, so one HMAC block always covers T.
            self.rehash_v();
            let k = BigUint::from_bytes_be(&self.v[..self.rlen])
                >> (8 * self.rlen as u64 - self.qlen);
            // Advance state before returning so a retry (r == 0, s == 0 or
            // k out of range) never yields the same k again.
            let nk = hmac_streebog512(self.k.as_ref(), &[self.v.as_ref(), &[0u8]]);
            *self.k = *nk;
            self.rehash_v();
            if !k.is_zero() && &k < self.q {
                return k;
            }
        }
    }
}

/// HMAC_GOSTR3411_2012_512 (RFC 7836 §4.1.2) over the concatenation of `parts`.
/// Keys are at most 64 bytes here, the Streebog block size.
fn hmac_streebog512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    debug_assert!(key.len() <= 64);
    let mut pad = Zeroizing::new([0u8; 64]);
    pad[..key.len()].copy_from_slice(key);
    for b in pad.iter_mut() {
        *b ^= 0x36;
    }
    let mut inner = Streebog512::new();
    inner.update(pad.as_ref());
    for p in parts {
        inner.update(p);
    }
    let mut ih = inner.finalize();
    for b in pad.iter_mut() {
        *b ^= 0x36 ^ 0x5c;
    }
    let mut outer = Streebog512::new();
    outer.update(pad.as_ref());
    outer.update(&ih);
    ih.as_mut_slice().zeroize();
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&outer.finalize());
    out
}

fn random_nonzero_below(q: &BigUint, width: usize, rng: &mut impl RngCore) -> BigUint {
    // Rejection sampling avoids modulo bias. For curves where q is well below
    // 2^(8*width) (e.g. TC26 256 paramSetA, q ~ 2^254) about 3 in 4 draws are
    // rejected; still cheap.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn hmac_streebog512_rfc7836_vector() {
        let key: Vec<u8> = (0u8..32).collect();
        let data = h("0126bdb87800af214341456563780100");
        let mac = hmac_streebog512(&key, &[&data]);
        assert_eq!(
            hex::encode(mac.as_ref()),
            "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77\
             3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6"
        );
    }

    fn n(x: &str) -> BigUint {
        BigUint::parse_bytes(x.as_bytes(), 16).unwrap()
    }

    /// GOST R 34.10-2012, Appendix A.1 (256-bit test curve, fixed k).
    #[test]
    fn gost_r_34_10_2012_appendix_a1() {
        let curve = Curve {
            oid: "test",
            name: "GOST R 34.10-2012 A.1 test curve",
            bytes: 32,
            p: n("8000000000000000000000000000000000000000000000000000000000000431"),
            q: n("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
            a: n("7"),
            b: n("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
            gx: n("2"),
            gy: n("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
        };
        let d = n("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
        let e = n("2DFBC1B372D89A1188C09C52E0EEC61FCE52032AB1022E8E67ECE6672B043EE5");
        let k = n("77105C9B20BCD3122823C8CF6FCC7B956DE33814E95B7FE64FED924594DCEAB3");
        let r = "41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493";
        let s = "01456c64ba4642a1653c235a98a60249bcd6d3f746b631df928014f6c5bf9c40";

        let q = curves::public_key(&curve, &d).unwrap();
        assert_eq!(
            q.x,
            n("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B")
        );
        assert_eq!(
            q.y,
            n("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA")
        );

        let sig = sign_with_k(&curve, &d, &e, &k).unwrap().unwrap();
        assert_eq!(hex::encode(&sig), format!("{s}{r}"));

        // The digest is read as a little-endian integer (CryptoPro convention).
        let digest = curves::le_fixed(&e, 32);
        let x = curves::le_fixed(&q.x, 32);
        let y = curves::le_fixed(&q.y, 32);
        assert!(verify_digest(&curve, &x, &y, &digest, &sig).unwrap());
        let mut bad = sig.clone();
        bad[63] ^= 1;
        assert!(!verify_digest(&curve, &x, &y, &digest, &bad).unwrap());
    }

    fn curves_under_test() -> Vec<Curve> {
        [
            "1.2.643.7.1.2.1.1.1",
            "1.2.643.7.1.2.1.1.2",
            "1.2.643.7.1.2.1.1.3",
            "1.2.643.7.1.2.1.1.4",
            "1.2.643.7.1.2.1.2.1",
            "1.2.643.7.1.2.1.2.2",
            "1.2.643.7.1.2.1.2.3",
        ]
        .iter()
        .filter_map(|oid| curves::by_oid(oid))
        .collect()
    }

    #[test]
    fn nonce_is_deterministic_in_inputs_and_in_range() {
        for curve in curves_under_test() {
            let d = BigUint::from(123456789u64);
            let e1 = BigUint::from(1u8);
            let e2 = BigUint::from(2u8);
            let zero = [0u8; 32];
            let a = NonceGen::new(&curve.q, &d, &e1, &zero).next();
            let b = NonceGen::new(&curve.q, &d, &e1, &zero).next();
            assert_eq!(a, b, "same inputs must give the same k");
            assert!(!a.is_zero() && a < curve.q);
            // A stuck RNG (same extra) must still give distinct k per digest.
            let c = NonceGen::new(&curve.q, &d, &e2, &zero).next();
            assert_ne!(a, c);
            // Fresh entropy changes k for the same digest.
            let other = [0x5au8; 32];
            assert_ne!(a, NonceGen::new(&curve.q, &d, &e1, &other).next());
            // Successive candidates differ (retry path).
            let mut g = NonceGen::new(&curve.q, &d, &e1, &zero);
            let k1 = g.next();
            let k2 = g.next();
            assert_ne!(k1, k2);
            assert!(!k2.is_zero() && k2 < curve.q);
        }
    }

    #[test]
    fn sign_verify_all_curves() {
        for curve in curves_under_test() {
            let d = BigUint::from(987654321u64);
            let p = curves::public_key(&curve, &d).unwrap();
            let private = curves::le_fixed(&d, curve.bytes);
            let x = curves::le_fixed(&p.x, curve.bytes);
            let y = curves::le_fixed(&p.y, curve.bytes);
            let digest = vec![0x42u8; curve.bytes];
            let s1 = sign_digest(&curve, &private, &digest).unwrap();
            let s2 = sign_digest(&curve, &private, &digest).unwrap();
            assert!(verify_digest(&curve, &x, &y, &digest, &s1).unwrap());
            assert!(verify_digest(&curve, &x, &y, &digest, &s2).unwrap());
            // Hedged: fresh entropy makes repeated signatures differ.
            assert_ne!(s1, s2);
        }
    }
}
