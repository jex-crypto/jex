// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use anyhow::{bail, Context, Result};

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + value.len());
    out.push(tag);
    encode_len(value.len(), &mut out);
    out.extend_from_slice(value);
    out
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len() - 1);
    let body = &bytes[first..];
    out.push(0x80 | body.len() as u8);
    out.extend_from_slice(body);
}

pub fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let value = concat(parts);
    tlv(0x30, &value)
}

pub fn set(mut parts: Vec<Vec<u8>>) -> Vec<u8> {
    // DER SET OF ordering is lexicographic over each element's complete DER encoding.
    parts.sort();
    tlv(0x31, &concat(&parts))
}

pub fn implicit_set0_from_der_set(der_set: &[u8]) -> Result<Vec<u8>> {
    let (tag, value) = split_tlv(der_set)?;
    if tag != 0x31 {
        bail!("expected DER SET (0x31), got 0x{tag:02x}");
    }
    Ok(tlv(0xA0, value))
}

pub fn implicit_set1_from_der_set(der_set: &[u8]) -> Result<Vec<u8>> {
    let (tag, value) = split_tlv(der_set)?;
    if tag != 0x31 {
        bail!("expected DER SET (0x31), got 0x{tag:02x}");
    }
    Ok(tlv(0xA1, value))
}

pub fn boolean(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

pub fn integer_unsigned(bytes: &[u8]) -> Vec<u8> {
    let first_nonzero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut body = if bytes.is_empty() {
        vec![0]
    } else {
        bytes[first_nonzero..].to_vec()
    };
    if body.is_empty() {
        body.push(0);
    }
    if body[0] & 0x80 != 0 {
        body.insert(0, 0);
    }
    tlv(0x02, &body)
}

pub fn explicit0(inner: &[u8]) -> Vec<u8> {
    tlv(0xA0, inner)
}

pub fn implicit0(value: &[u8]) -> Vec<u8> {
    tlv(0xA0, value)
}

pub fn integer_u8(value: u8) -> Vec<u8> {
    if value < 0x80 {
        tlv(0x02, &[value])
    } else {
        tlv(0x02, &[0, value])
    }
}

pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

pub fn utf8_string(value: &str) -> Vec<u8> {
    tlv(0x0C, value.as_bytes())
}

/// UTCTime `YYMMDDHHMMSSZ` (tag 0x17).
pub fn utc_time_yy(unix: i64) -> Result<Vec<u8>> {
    let (y, mon, d, h, mi, s) = civil_from_unix(unix)?;
    let yy = if (1950..2050).contains(&y) {
        y % 100
    } else {
        bail!("UTCTime year out of range: {y}");
    };
    let body = format!("{yy:02}{mon:02}{d:02}{h:02}{mi:02}{s:02}Z");
    Ok(tlv(0x17, body.as_bytes()))
}

pub fn generalized_time(unix: i64) -> Result<Vec<u8>> {
    let (y, mon, d, h, mi, s) = civil_from_unix(unix)?;
    let body = format!("{y:04}{mon:02}{d:02}{h:02}{mi:02}{s:02}Z");
    Ok(tlv(0x18, body.as_bytes()))
}

pub fn ia5_string(value: &str) -> Vec<u8> {
    tlv(0x16, value.as_bytes())
}

/// Context-specific primitive tag `0x80 | n`.
pub fn context_primitive(n: u8, value: &[u8]) -> Vec<u8> {
    tlv(0x80 | n, value)
}

/// Context-specific constructed tag `0xa0 | n`.
pub fn context_constructed(n: u8, value: &[u8]) -> Vec<u8> {
    tlv(0xa0 | n, value)
}

fn civil_from_unix(unix: i64) -> Result<(i32, u32, u32, u32, u32, u32)> {
    // Howard Hinnant civil_from_days.
    let secs = unix;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64 + era * 400) as i32;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Ok((y, m, d, h, mi, s))
}

pub fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(value.len() + 1);
    body.push(0); // unused bits
    body.extend_from_slice(value);
    tlv(0x03, &body)
}

pub fn oid(oid: &str) -> Result<Vec<u8>> {
    let arcs = oid
        .split('.')
        .map(|p| {
            p.parse::<u64>()
                .with_context(|| format!("bad OID arc {p:?} in {oid}"))
        })
        .collect::<Result<Vec<_>>>()?;
    if arcs.len() < 2 {
        bail!("OID must have at least two arcs: {oid}");
    }
    if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
        bail!("invalid first OID arcs: {oid}");
    }
    let mut body = Vec::new();
    push_base128(arcs[0] * 40 + arcs[1], &mut body);
    for &arc in &arcs[2..] {
        push_base128(arc, &mut body);
    }
    Ok(tlv(0x06, &body))
}

fn push_base128(mut value: u64, out: &mut Vec<u8>) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    i -= 1;
    tmp[i] = (value & 0x7f) as u8;
    value >>= 7;
    while value != 0 {
        i -= 1;
        tmp[i] = 0x80 | (value & 0x7f) as u8;
        value >>= 7;
    }
    out.extend_from_slice(&tmp[i..]);
}

pub fn algorithm_identifier(oid_text: &str) -> Result<Vec<u8>> {
    // RFC 9215 requires GOST 2012 digest/signature AlgorithmIdentifier
    // parameters to be omitted, not NULL.
    Ok(sequence(&[oid(oid_text)?]))
}

pub fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    let len = parts.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(len);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

pub fn split_tlv(input: &[u8]) -> Result<(u8, &[u8])> {
    if input.len() < 2 {
        bail!("truncated DER TLV");
    }
    let tag = input[0];
    let (len, len_len) = parse_len(&input[1..])?;
    let header = 1 + len_len;
    let end = header.checked_add(len).context("DER length overflow")?;
    if end != input.len() {
        bail!(
            "DER TLV length mismatch: encoded {end}, buffer {}",
            input.len()
        );
    }
    Ok((tag, &input[header..end]))
}

fn parse_len(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input.first().context("missing DER length")?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > std::mem::size_of::<usize>() || input.len() < 1 + n {
        bail!("invalid DER long-form length");
    }
    let mut len = 0usize;
    for &b in &input[1..1 + n] {
        len = len
            .checked_mul(256)
            .and_then(|x| x.checked_add(b as usize))
            .context("DER length overflow")?;
    }
    Ok((len, 1 + n))
}
