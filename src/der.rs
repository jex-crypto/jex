// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub total_len: usize,
}

pub fn parse_tlv(input: &[u8]) -> Result<Tlv<'_>> {
    if input.len() < 2 {
        bail!("truncated DER TLV");
    }
    let tag = input[0];
    let (len, len_len) = parse_len(&input[1..])?;
    let header_len = 1 + len_len;
    let total_len = header_len.checked_add(len).context("DER length overflow")?;
    if total_len > input.len() {
        bail!(
            "DER value is truncated: need {total_len}, have {}",
            input.len()
        );
    }
    Ok(Tlv {
        tag,
        value: &input[header_len..total_len],
        total_len,
    })
}

fn parse_len(input: &[u8]) -> Result<(usize, usize)> {
    let first = *input.first().context("missing DER length")?;
    if first & 0x80 == 0 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 {
        bail!("indefinite DER length is not allowed");
    }
    if n > std::mem::size_of::<usize>() || input.len() < 1 + n {
        bail!("invalid DER long-form length");
    }
    let mut len = 0usize;
    for &b in &input[1..1 + n] {
        len = len
            .checked_mul(256)
            .and_then(|v| v.checked_add(b as usize))
            .context("DER length overflow")?;
    }
    Ok((len, 1 + n))
}

pub fn children(seq_value: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    let mut rest = seq_value;
    while !rest.is_empty() {
        let tlv = parse_tlv(rest)?;
        out.push(tlv);
        rest = &rest[tlv.total_len..];
    }
    Ok(out)
}

pub fn parse_sequence(input: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let top = parse_tlv(input)?;
    if top.tag != 0x30 {
        bail!("expected DER SEQUENCE (0x30), got 0x{:02x}", top.tag);
    }
    children(top.value)
}

pub fn collect_oids(input: &[u8]) -> Vec<String> {
    fn walk(buf: &[u8], out: &mut Vec<String>) {
        let mut rest = buf;
        while !rest.is_empty() {
            let Ok(tlv) = parse_tlv(rest) else { return };
            if tlv.tag == 0x06 {
                if let Some(oid) = decode_oid(tlv.value) {
                    out.push(oid);
                }
            }
            if tlv.tag & 0x20 != 0 {
                walk(tlv.value, out);
            }
            if tlv.total_len == 0 || tlv.total_len > rest.len() {
                return;
            }
            rest = &rest[tlv.total_len..];
        }
    }

    let mut out = Vec::new();
    walk(input, &mut out);
    out.sort();
    out.dedup();
    out
}

pub fn find_context_primitive<'a>(
    input: &'a [u8],
    tag: u8,
    expected_len: usize,
) -> Option<&'a [u8]> {
    fn walk<'a>(buf: &'a [u8], tag: u8, expected_len: usize) -> Option<&'a [u8]> {
        let mut rest = buf;
        while !rest.is_empty() {
            let tlv = parse_tlv(rest).ok()?;
            if tlv.tag == tag && tlv.value.len() == expected_len {
                return Some(tlv.value);
            }
            if tlv.tag & 0x20 != 0 {
                if let Some(v) = walk(tlv.value, tag, expected_len) {
                    return Some(v);
                }
            }
            rest = rest.get(tlv.total_len..)?;
        }
        None
    }
    walk(input, tag, expected_len)
}

pub fn decode_oid(body: &[u8]) -> Option<String> {
    let first = *body.first()? as u64;
    let (a, b) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };

    let mut parts = vec![a, b];
    let mut cur = 0u64;
    let mut in_component = false;
    for &x in &body[1..] {
        in_component = true;
        cur = cur.checked_mul(128)?.checked_add((x & 0x7f) as u64)?;
        if x & 0x80 == 0 {
            parts.push(cur);
            cur = 0;
            in_component = false;
        }
    }
    if in_component {
        return None;
    }
    Some(
        parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}
