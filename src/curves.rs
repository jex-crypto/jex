// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use anyhow::{bail, Result};
use num_bigint::BigUint;
use num_traits::{One, Zero};

#[derive(Clone, Debug)]
pub struct Curve {
    pub oid: &'static str,
    pub name: &'static str,
    pub bytes: usize,
    pub p: BigUint,
    pub q: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
}

fn n(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid curve hex")
}

fn curve(
    oid: &'static str,
    name: &'static str,
    bytes: usize,
    p: &str,
    q: &str,
    a: &str,
    b: &str,
    gx: &str,
    gy: &str,
) -> Curve {
    Curve {
        oid,
        name,
        bytes,
        p: n(p),
        q: n(q),
        a: n(a),
        b: n(b),
        gx: n(gx),
        gy: n(gy),
    }
}

pub fn by_oid(oid: &str) -> Option<Curve> {
    match oid {
        "1.2.643.7.1.2.1.1.1" => Some(curve(
            "1.2.643.7.1.2.1.1.1", "TC26 2012-256 paramSetA", 32,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
            "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67",
            "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335",
            "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513",
            "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28",
            "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C",
        )),
        // TC26 2012-256 B/C/D deliberately reuse the legacy CryptoPro curves.
        "1.2.643.7.1.2.1.1.2" | "1.2.643.2.2.35.1" | "1.2.643.2.2.36.0" => Some(curve(
            "1.2.643.7.1.2.1.1.2", "CryptoPro-A / TC26 2012-256 paramSetB", 32,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
            "A6",
            "1",
            "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
        )),
        "1.2.643.7.1.2.1.1.3" | "1.2.643.2.2.35.2" => Some(curve(
            "1.2.643.7.1.2.1.1.3", "CryptoPro-B / TC26 2012-256 paramSetC", 32,
            "8000000000000000000000000000000000000000000000000000000000000C99",
            "800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F",
            "8000000000000000000000000000000000000000000000000000000000000C96",
            "3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B",
            "1",
            "3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC",
        )),
        "1.2.643.7.1.2.1.1.4" | "1.2.643.2.2.35.3" | "1.2.643.2.2.36.1" => Some(curve(
            "1.2.643.7.1.2.1.1.4", "CryptoPro-C / TC26 2012-256 paramSetD", 32,
            "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B",
            "9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9",
            "9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598",
            "805A",
            "0",
            "41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67",
        )),
        "1.2.643.7.1.2.1.2.1" => Some(curve(
            "1.2.643.7.1.2.1.2.1", "TC26 2012-512 paramSetA", 64,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
            "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
            "3",
            "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
        )),
        "1.2.643.7.1.2.1.2.2" => Some(curve(
            "1.2.643.7.1.2.1.2.2", "TC26 2012-512 paramSetB", 64,
            "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
            "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
            "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
            "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
            "2",
            "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
        )),
        "1.2.643.7.1.2.1.2.3" => Some(curve(
            "1.2.643.7.1.2.1.2.3", "TC26 2012-512 paramSetC", 64,
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
            "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
            "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
            "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
            "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
        )),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct Point {
    pub x: BigUint,
    pub y: BigUint,
}

fn mod_sub(a: &BigUint, b: &BigUint, p: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % p
    } else {
        (p - ((b - a) % p)) % p
    }
}

fn inv_prime(v: &BigUint, p: &BigUint) -> Result<BigUint> {
    if v.is_zero() {
        bail!("modular inverse of zero");
    }
    Ok(v.modpow(&(p - BigUint::from(2u8)), p))
}

fn add(curve: &Curve, p1: Option<Point>, p2: Option<Point>) -> Result<Option<Point>> {
    match (p1, p2) {
        (None, q) => Ok(q),
        (p, None) => Ok(p),
        (Some(p1), Some(p2)) => {
            if p1.x == p2.x && (&p1.y + &p2.y) % &curve.p == BigUint::zero() {
                return Ok(None);
            }
            let lambda = if p1.x == p2.x && p1.y == p2.y {
                let num = (BigUint::from(3u8) * &p1.x * &p1.x + &curve.a) % &curve.p;
                let den = (BigUint::from(2u8) * &p1.y) % &curve.p;
                (num * inv_prime(&den, &curve.p)?) % &curve.p
            } else {
                let num = mod_sub(&p2.y, &p1.y, &curve.p);
                let den = mod_sub(&p2.x, &p1.x, &curve.p);
                (num * inv_prime(&den, &curve.p)?) % &curve.p
            };
            let x3 = mod_sub(
                &mod_sub(&((&lambda * &lambda) % &curve.p), &p1.x, &curve.p),
                &p2.x,
                &curve.p,
            );
            let y3 = mod_sub(
                &((&lambda * mod_sub(&p1.x, &x3, &curve.p)) % &curve.p),
                &p1.y,
                &curve.p,
            );
            Ok(Some(Point { x: x3, y: y3 }))
        }
    }
}

fn scalar_mul_optional(curve: &Curve, point: &Point, scalar: &BigUint) -> Result<Option<Point>> {
    let mut k = scalar.clone();
    let mut acc: Option<Point> = None;
    let mut base = Some(point.clone());
    while !k.is_zero() {
        if (&k & BigUint::one()) == BigUint::one() {
            acc = add(curve, acc, base.clone())?;
        }
        base = add(curve, base.clone(), base)?;
        k >>= 1usize;
    }
    Ok(acc)
}

pub fn scalar_mul_generator(curve: &Curve, scalar: &BigUint) -> Result<Point> {
    if scalar.is_zero() || scalar >= &curve.q {
        bail!("scalar is outside 1..q-1");
    }
    let g = Point {
        x: curve.gx.clone(),
        y: curve.gy.clone(),
    };
    scalar_mul_optional(curve, &g, scalar)?
        .ok_or_else(|| anyhow::anyhow!("scalar multiplication returned infinity"))
}

pub fn scalar_mul_point(curve: &Curve, point: &Point, scalar: &BigUint) -> Result<Point> {
    if scalar.is_zero() || scalar >= &curve.q {
        bail!("scalar is outside 1..q-1");
    }
    if !is_on_curve(curve, point) {
        bail!("public point is not on the selected curve");
    }
    scalar_mul_optional(curve, point, scalar)?
        .ok_or_else(|| anyhow::anyhow!("scalar multiplication returned infinity"))
}

pub fn add_public(curve: &Curve, p1: Option<Point>, p2: Option<Point>) -> Result<Option<Point>> {
    add(curve, p1, p2)
}

pub fn is_on_curve(curve: &Curve, point: &Point) -> bool {
    if &point.x >= &curve.p || &point.y >= &curve.p {
        return false;
    }
    let lhs = (&point.y * &point.y) % &curve.p;
    let rhs =
        ((&point.x * &point.x % &curve.p) * &point.x + &curve.a * &point.x + &curve.b) % &curve.p;
    lhs == rhs
}

pub fn public_key(curve: &Curve, d: &BigUint) -> Result<Point> {
    scalar_mul_generator(curve, d)
}

pub fn remove_mask(curve: &Curve, protected: &BigUint, mask: &BigUint) -> Result<BigUint> {
    if mask.is_zero() {
        bail!("zero private-key mask");
    }
    let inv = mask.modpow(&(&curve.q - BigUint::from(2u8)), &curve.q);
    Ok((protected * inv) % &curve.q)
}

/// Inverse of [`remove_mask`]: `protected = (d * mask) mod q`.
pub fn apply_mask(curve: &Curve, d: &BigUint, mask: &BigUint) -> Result<BigUint> {
    if mask.is_zero() {
        bail!("zero private-key mask");
    }
    if d.is_zero() {
        bail!("zero private scalar");
    }
    Ok((d * mask) % &curve.q)
}

pub fn le_fixed(v: &BigUint, n: usize) -> Vec<u8> {
    let mut out = v.to_bytes_le();
    out.resize(n, 0);
    out.truncate(n);
    out
}
