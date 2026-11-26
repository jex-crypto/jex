// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::{archive, cades, xlong};
use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CadesProfile {
    Bes,
    T,
    XLongType1,
    A,
}

impl CadesProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bes => "CAdES-BES",
            Self::T => "CAdES-T",
            Self::XLongType1 => "CAdES-X Long Type 1",
            Self::A => "CAdES-A",
        }
    }
}

#[derive(Debug)]
pub struct LocalVerification {
    pub profile: CadesProfile,
    pub base: cades::VerifyResult,
    pub xlong_audit: Option<xlong::XLongAudit>,
    pub archive_count: usize,
    pub archive_audit: Option<archive::ArchiveAudit>,
    pub partial_xlong: bool,
}

impl LocalVerification {
    pub fn base_valid(&self) -> bool {
        self.base.message_digest_valid
            && self.base.signing_certificate_v2_valid
            && self.base.signer_id_matches_certificate
            && self.base.signature_valid
            && self.base.timestamp_imprint_valid.unwrap_or(true)
            && self.base.timestamp_token_signature_valid.unwrap_or(true)
            && self
                .base
                .timestamp_token_certificate_valid_at_gen_time
                .unwrap_or(true)
    }

    pub fn is_valid(&self) -> bool {
        if !self.base_valid() || self.partial_xlong {
            return false;
        }
        if let Some(audit) = &self.xlong_audit {
            if !audit.is_conformant() {
                return false;
            }
        }
        if self.archive_count > 0 {
            let Some(audit) = &self.archive_audit else {
                return false;
            };
            if !audit.is_conformant() {
                return false;
            }
        }
        true
    }
}

/// Analyze and locally verify the strongest CAdES profile present in `input`.
///
/// This function verifies cryptographic integrity and all profile semantics
/// implemented by this crate. It intentionally does not make a system PKI
/// trust-anchor or revocation-policy decision.
pub fn analyze(input: &[u8], external_content: Option<&[u8]>) -> Result<LocalVerification> {
    analyze_ex(
        input,
        external_content.map(archive::ExternalData::Content),
    )
}

pub fn analyze_ex(
    input: &[u8],
    external: Option<archive::ExternalData<'_>>,
) -> Result<LocalVerification> {
    let (content, digest) = match external {
        Some(archive::ExternalData::Content(c)) => (Some(c), None),
        Some(archive::ExternalData::Digest(h)) => (None, Some(h)),
        None => (None, None),
    };
    let base = cades::verify_ex(input, content, digest)?;
    let xlong_presence = xlong::inspect_presence(input)?;
    let archive_count = archive::archive_timestamp_v3_count(input)?;

    // A signature timestamp alone is CAdES-T. Any of the five XLT1-specific
    // attributes means the object is attempting XLT1 and must contain the full
    // set rather than silently falling back to T/BES.
    let has_any_xlong_specific = xlong_presence.certificate_refs
        || xlong_presence.revocation_refs
        || xlong_presence.certificate_values
        || xlong_presence.revocation_values
        || xlong_presence.esc_timestamp;
    let partial_xlong = has_any_xlong_specific && !xlong_presence.is_x_long_type_1();

    let xlong_audit = if xlong_presence.is_x_long_type_1() {
        Some(xlong::audit_x_long_type_1(input))
    } else {
        None
    };
    let archive_audit = if archive_count > 0 {
        Some(archive::audit_cades_a(input, external))
    } else {
        None
    };

    let profile = if archive_count > 0 {
        CadesProfile::A
    } else if xlong_presence.is_x_long_type_1() {
        CadesProfile::XLongType1
    } else if base.timestamp_imprint_valid.is_some() {
        CadesProfile::T
    } else {
        CadesProfile::Bes
    };

    Ok(LocalVerification {
        profile,
        base,
        xlong_audit,
        archive_count,
        archive_audit,
        partial_xlong,
    })
}
