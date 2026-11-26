// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Clean web API under `/api/v1` (no CryptoPro CADESCOM surface).

use super::{
    authorize_request, cert_thumbprint_sha1, enhance_cms, parse_enhance_profile, pick_key_id,
    respond_json_cors, sign_with_key_full, ApiAcl, Runtime, CADES_BES,
};
use crate::{archive, cades, verification, x509};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{io::Read as _, sync::Arc};
use tiny_http::{Method, Request};

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: ApiError,
}

#[derive(Debug, Serialize)]
struct ApiError {
    code: &'static str,
    message: String,
}

fn respond_err(
    request: Request,
    code: u16,
    err_code: &'static str,
    message: impl Into<String>,
    origin: Option<&str>,
    acl: &ApiAcl,
) -> Result<()> {
    respond_json_cors(
        request,
        code,
        &ApiErrorBody {
            error: ApiError {
                code: err_code,
                message: message.into(),
            },
        },
        origin,
        acl,
    )
}

fn auth_err(
    request: Request,
    code: u16,
    msg: String,
    origin: Option<&str>,
    acl: &ApiAcl,
) -> Result<()> {
    let err_code = if code == 403 {
        "forbidden_key"
    } else {
        "unauthorized"
    };
    respond_err(request, code, err_code, msg, origin, acl)
}

/// Dispatch `/api/v1` and `/api/v1/*`.
pub(super) fn try_handle(
    rt: Arc<Runtime>,
    request: Request,
    method: &Method,
    path: &str,
    origin: Option<&str>,
) -> Result<()> {
    if path == "/api/v1" || path == "/api/v1/" {
        if *method == Method::Get {
            return handle_discovery(rt, request, origin);
        }
        return respond_err(
            request,
            405,
            "invalid_json",
            "use GET for discovery",
            origin,
            &rt.acl,
        );
    }

    match (method, path) {
        (Method::Get, "/api/v1/keys") => handle_keys(rt, request, origin),
        (Method::Post, "/api/v1/sign") => handle_sign(rt, request, origin),
        (Method::Post, "/api/v1/verify") => handle_verify(rt, request, origin),
        (Method::Post, "/api/v1/enhance") => handle_enhance(rt, request, origin),
        (Method::Post, "/api/v1/convert") => handle_convert(rt, request, origin),
        (Method::Post, "/api/v1/hash") => handle_hash(rt, request, origin),
        _ => respond_err(
            request,
            404,
            "missing_field",
            format!("unknown path {path}"),
            origin,
            &rt.acl,
        ),
    }
}

fn handle_discovery(rt: Arc<Runtime>, request: Request, origin: Option<&str>) -> Result<()> {
    let body = json!({
        "name": "jex",
        "api": "v1",
        "profiles": ["bes", "t", "xlt1", "a"],
        "hash_algs": ["streebog256", "streebog512"],
        "features": {
            "sign": true,
            "verify": true,
            "enhance": true,
            "convert": true,
            "hash": true,
            "archive": true,
            "default_tsa": rt.default_tsa.is_some(),
        }
    });
    respond_json_cors(request, 200, &body, origin, &rt.acl)
}

fn handle_keys(rt: Arc<Runtime>, request: Request, origin: Option<&str>) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => return auth_err(request, code, msg, origin, &rt.acl),
    };
    let keys: Vec<_> = rt
        .acl
        .visible_ids(entry, &rt.store)
        .into_iter()
        .filter_map(|id| rt.store.get(id))
        .map(|k| {
            json!({
                "id": k.id,
                "subject": k.subject,
                "serial_hex": k.serial_hex,
                "thumbprint": k.thumbprint,
                "not_before": k.not_before,
                "not_after": k.not_after,
                "curve": k.curve.name,
            })
        })
        .collect();
    respond_json_cors(request, 200, &keys, origin, &rt.acl)
}

#[derive(Debug, Deserialize)]
struct ContentIn {
    b64: Option<String>,
    hash_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlobIn {
    b64: String,
}

#[derive(Debug, Deserialize)]
struct SignRequest {
    key_id: Option<String>,
    #[serde(default = "default_bes")]
    profile: String,
    #[serde(default = "default_detached")]
    mode: String,
    content: ContentIn,
    tsa: Option<String>,
}

fn default_bes() -> String {
    "bes".into()
}
fn default_detached() -> String {
    "detached".into()
}
fn default_xlt1() -> String {
    "xlt1".into()
}

fn parse_content(c: &ContentIn) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), (&'static str, String)> {
    match (c.b64.as_deref(), c.hash_hex.as_deref()) {
        (Some(b64), None) => {
            let bytes = STANDARD
                .decode(b64.trim())
                .map_err(|e| ("invalid_base64", format!("invalid content.b64: {e}")))?;
            Ok((Some(bytes), None))
        }
        (None, Some(hex_s)) => {
            let h = hex::decode(hex_s.trim()).map_err(|e| {
                (
                    "invalid_content",
                    format!("invalid content.hash_hex: {e}"),
                )
            })?;
            Ok((None, Some(h)))
        }
        (Some(_), Some(_)) => Err((
            "invalid_content",
            "pass content.b64 or content.hash_hex, not both".into(),
        )),
        (None, None) => Err((
            "invalid_content",
            "content.b64 or content.hash_hex required".into(),
        )),
    }
}

fn parse_mode(mode: &str) -> Result<bool, (&'static str, String)> {
    match mode.trim().to_ascii_lowercase().as_str() {
        "detached" => Ok(true),
        "attached" => Ok(false),
        other => Err((
            "invalid_mode",
            format!("unknown mode '{other}' (expected detached|attached)"),
        )),
    }
}

fn parse_sign_profile(s: &str) -> Result<u32, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "bes" | "cades-bes" | "cades_bes" => Ok(CADES_BES),
        other => parse_enhance_profile(other).map_err(|e| format!("{e:#}")),
    }
}

fn profile_short_from_name(s: &str) -> &'static str {
    match s {
        "CAdES-BES" => "bes",
        "CAdES-T" => "t",
        "CAdES-XLT1" | "CAdES-X Long Type 1" => "xlt1",
        "CAdES-A" => "a",
        _ => "bes",
    }
}

fn profile_short_from_enum(p: verification::CadesProfile) -> &'static str {
    match p {
        verification::CadesProfile::Bes => "bes",
        verification::CadesProfile::T => "t",
        verification::CadesProfile::XLongType1 => "xlt1",
        verification::CadesProfile::A => "a",
    }
}

fn digest_alg_name(oid: &str) -> &'static str {
    if oid == cades::OID_DIGEST_512 {
        "streebog512"
    } else {
        "streebog256"
    }
}

fn decode_blob(b: &BlobIn) -> Result<Vec<u8>, (&'static str, String)> {
    STANDARD
        .decode(b.b64.trim())
        .map_err(|e| ("invalid_base64", format!("invalid b64: {e}")))
}

fn read_json<T: for<'de> Deserialize<'de>>(
    request: &mut Request,
) -> Result<T, (&'static str, String)> {
    let mut body = Vec::new();
    request
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|e| ("internal", format!("read body: {e}")))?;
    serde_json::from_slice(&body).map_err(|e| ("invalid_json", format!("invalid JSON body: {e}")))
}

fn signer_json(cert: &[u8]) -> serde_json::Value {
    let subject = x509::subject_name_attributes(cert)
        .ok()
        .and_then(|a| x509::display_name_from_attrs(&a));
    json!({
        "subject": subject,
        "thumbprint": cert_thumbprint_sha1(cert),
    })
}

fn handle_sign(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    let entry = match authorize_request(&rt.acl, &request, origin) {
        Ok(e) => e,
        Err((code, msg)) => return auth_err(request, code, msg, origin, &rt.acl),
    };
    let parsed: SignRequest = match read_json(&mut request) {
        Ok(p) => p,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let (content, digest) = match parse_content(&parsed.content) {
        Ok(v) => v,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let detached = match parse_mode(&parsed.mode) {
        Ok(d) => d,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    if digest.is_some() && !detached {
        return respond_err(
            request,
            400,
            "invalid_mode",
            "content.hash_hex requires mode detached",
            origin,
            &rt.acl,
        );
    }
    let target = match parse_sign_profile(&parsed.profile) {
        Ok(t) => t,
        Err(e) => return respond_err(request, 400, "invalid_profile", e, origin, &rt.acl),
    };

    let key_id = match pick_key_id(entry, &rt.store, parsed.key_id.as_deref(), &rt.acl) {
        Ok(id) => id,
        Err((code, msg)) => {
            let err_code = if msg.contains("no signing") {
                "no_keys"
            } else if code == 403 {
                "forbidden_key"
            } else if code == 400 {
                "key_required"
            } else {
                "unauthorized"
            };
            return respond_err(request, code, err_code, msg, origin, &rt.acl);
        }
    };
    let key = match rt.store.get(&key_id) {
        Some(k) => k,
        None => {
            return respond_err(
                request,
                404,
                "forbidden_key",
                "key not found",
                origin,
                &rt.acl,
            )
        }
    };

    let content_bytes = content.unwrap_or_default();
    let digest_ref = digest.as_deref();
    if content_bytes.is_empty() && digest_ref.is_none() {
        return respond_err(
            request,
            400,
            "invalid_content",
            "empty content",
            origin,
            &rt.acl,
        );
    }

    match sign_with_key_full(
        &rt,
        key,
        &content_bytes,
        digest_ref,
        !detached,
        parsed.tsa.as_deref(),
        target,
        &[],
    ) {
        Ok(resp) => {
            let der = STANDARD.decode(&resp.signature_b64).unwrap_or_default();
            let cms = cades::parse(&der).ok();
            let detached_out = cms.as_ref().map(|p| p.detached).unwrap_or(detached);
            let digest_oid = cms
                .as_ref()
                .map(|p| p.digest_oid.as_str())
                .unwrap_or(cades::OID_DIGEST_256);
            respond_json_cors(
                request,
                200,
                &json!({
                    "profile": profile_short_from_name(&resp.profile),
                    "detached": detached_out,
                    "signature": { "b64": resp.signature_b64 },
                    "digest": {
                        "alg": digest_alg_name(digest_oid),
                        "hex": resp.content_digest_hex,
                    },
                    "signer": {
                        "key_id": key.id,
                        "subject": key.subject,
                        "thumbprint": key.thumbprint,
                    }
                }),
                origin,
                &rt.acl,
            )
        }
        Err(e) => {
            let msg = format!("{e:#}");
            let code = if msg.contains("TSA") {
                "missing_tsa"
            } else {
                "internal"
            };
            respond_err(request, 500, code, msg, origin, &rt.acl)
        }
    }
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    signature: BlobIn,
    content: Option<ContentIn>,
}

fn handle_verify(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return auth_err(request, code, msg, origin, &rt.acl);
    }
    let parsed: VerifyRequest = match read_json(&mut request) {
        Ok(p) => p,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let der = match decode_blob(&parsed.signature) {
        Ok(d) => d,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let (content, digest) = match &parsed.content {
        Some(c) => match parse_content(c) {
            Ok(v) => v,
            Err((code, m)) => return respond_err(request, 400, code, m, origin, &rt.acl),
        },
        None => (None, None),
    };

    let external = match (&content, &digest) {
        (Some(c), None) => Some(archive::ExternalData::Content(c.as_slice())),
        (None, Some(h)) => Some(archive::ExternalData::Digest(h.as_slice())),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!(),
    };

    let report = match verification::analyze_ex(&der, external) {
        Ok(r) => r,
        Err(e) => {
            return respond_err(
                request,
                400,
                "verification_failed",
                format!("{e:#}"),
                origin,
                &rt.acl,
            )
        }
    };

    let cms = match cades::parse(&der) {
        Ok(p) => p,
        Err(e) => {
            return respond_err(
                request,
                400,
                "verification_failed",
                format!("{e:#}"),
                origin,
                &rt.acl,
            )
        }
    };
    let signer = signer_json(&cms.certificate);

    if !report.is_valid() {
        return respond_err(
            request,
            400,
            "verification_failed",
            format!(
                "local verification failed (profile {})",
                report.profile.as_str()
            ),
            origin,
            &rt.acl,
        );
    }

    respond_json_cors(
        request,
        200,
        &json!({
            "ok": true,
            "profile": profile_short_from_enum(report.profile),
            "detached": report.base.detached,
            "checks": {
                "signature": report.base.signature_valid,
                "message_digest": report.base.message_digest_valid,
                "signing_certificate_v2": report.base.signing_certificate_v2_valid,
            },
            "digest": {
                "alg": digest_alg_name(&cms.digest_oid),
                "hex": hex::encode(&cms.message_digest),
            },
            "signer": signer,
        }),
        origin,
        &rt.acl,
    )
}

#[derive(Debug, Deserialize)]
struct EnhanceRequest {
    signature: BlobIn,
    #[serde(default = "default_xlt1")]
    profile: String,
    content: Option<ContentIn>,
    tsa: Option<String>,
}

fn handle_enhance(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return auth_err(request, code, msg, origin, &rt.acl);
    }
    let parsed: EnhanceRequest = match read_json(&mut request) {
        Ok(p) => p,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let der = match decode_blob(&parsed.signature) {
        Ok(d) => d,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let (content, digest) = match &parsed.content {
        Some(c) => match parse_content(c) {
            Ok(v) => v,
            Err((code, m)) => return respond_err(request, 400, code, m, origin, &rt.acl),
        },
        None => (None, None),
    };
    let external =
        match archive::ExternalData::from_parts(content.as_deref(), digest.as_deref()) {
            Ok(e) => e,
            Err(e) => {
                return respond_err(
                    request,
                    400,
                    "invalid_content",
                    format!("{e:#}"),
                    origin,
                    &rt.acl,
                )
            }
        };
    let target = match parse_enhance_profile(&parsed.profile) {
        Ok(t) => t,
        Err(e) => {
            return respond_err(
                request,
                400,
                "invalid_profile",
                format!("{e:#}"),
                origin,
                &rt.acl,
            )
        }
    };
    let tsa = parsed
        .tsa
        .as_deref()
        .or(rt.default_tsa.as_deref())
        .map(|s| s.to_string());

    match enhance_cms(&rt, der, external, tsa, target) {
        Ok((out, profile_name)) => {
            let cms = cades::parse(&out)?;
            respond_json_cors(
                request,
                200,
                &json!({
                    "profile": profile_short_from_name(&profile_name),
                    "detached": cms.detached,
                    "signature": { "b64": STANDARD.encode(&out) },
                    "digest": {
                        "alg": digest_alg_name(&cms.digest_oid),
                        "hex": hex::encode(&cms.message_digest),
                    },
                    "signer": signer_json(&cms.certificate),
                }),
                origin,
                &rt.acl,
            )
        }
        Err(e) => {
            let msg = format!("{e:#}");
            let code = if msg.contains("TSA") {
                "missing_tsa"
            } else if msg.contains("message-digest") || msg.contains("content-hash") {
                "content_digest_mismatch"
            } else {
                "internal"
            };
            respond_err(request, 500, code, msg, origin, &rt.acl)
        }
    }
}

#[derive(Debug, Deserialize)]
struct ConvertRequest {
    signature: BlobIn,
    to: String,
    content: Option<ContentIn>,
}

fn handle_convert(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return auth_err(request, code, msg, origin, &rt.acl);
    }
    let parsed: ConvertRequest = match read_json(&mut request) {
        Ok(p) => p,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let der = match decode_blob(&parsed.signature) {
        Ok(d) => d,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let to = parsed.to.trim().to_ascii_lowercase();

    let (sig, content_out, detached) = match to.as_str() {
        "attached" => {
            let content = match &parsed.content {
                Some(c) => match parse_content(c) {
                    Ok((Some(bytes), None)) => bytes,
                    Ok(_) => {
                        return respond_err(
                            request,
                            400,
                            "invalid_content",
                            "convert to attached requires content.b64",
                            origin,
                            &rt.acl,
                        )
                    }
                    Err((code, m)) => return respond_err(request, 400, code, m, origin, &rt.acl),
                },
                None => {
                    return respond_err(
                        request,
                        400,
                        "missing_field",
                        "content required for to=attached",
                        origin,
                        &rt.acl,
                    )
                }
            };
            match archive::attach_original_content(&der, &content) {
                Ok(sig) => (sig, Some(content), false),
                Err(e) => {
                    let msg = format!("{e:#}");
                    let code = if msg.contains("already attached") {
                        "not_detached"
                    } else if msg.contains("message-digest") {
                        "content_digest_mismatch"
                    } else {
                        "internal"
                    };
                    return respond_err(request, 400, code, msg, origin, &rt.acl);
                }
            }
        }
        "detached" => match archive::detach_original_content(&der) {
            Ok((sig, content)) => (sig, Some(content), true),
            Err(e) => {
                let msg = format!("{e:#}");
                let code = if msg.contains("already detached") {
                    "not_attached"
                } else {
                    "internal"
                };
                return respond_err(request, 400, code, msg, origin, &rt.acl);
            }
        },
        other => {
            return respond_err(
                request,
                400,
                "invalid_mode",
                format!("unknown to '{other}' (expected attached|detached)"),
                origin,
                &rt.acl,
            )
        }
    };

    let report = if detached {
        verification::analyze(&sig, content_out.as_deref())
    } else {
        verification::analyze(&sig, None)
    };
    match &report {
        Ok(r) if r.is_valid() => {}
        Ok(_) => {
            return respond_err(
                request,
                400,
                "verification_failed",
                "converted signature failed local verification",
                origin,
                &rt.acl,
            )
        }
        Err(e) => {
            return respond_err(
                request,
                400,
                "verification_failed",
                format!("{e:#}"),
                origin,
                &rt.acl,
            )
        }
    }
    let report = report.unwrap();
    let cms = cades::parse(&sig)?;
    respond_json_cors(
        request,
        200,
        &json!({
            "profile": profile_short_from_enum(report.profile),
            "detached": detached,
            "signature": { "b64": STANDARD.encode(&sig) },
            "content": content_out.as_ref().map(|c| json!({ "b64": STANDARD.encode(c) })),
            "digest": {
                "alg": digest_alg_name(&cms.digest_oid),
                "hex": hex::encode(&cms.message_digest),
            },
            "signer": signer_json(&cms.certificate),
        }),
        origin,
        &rt.acl,
    )
}

#[derive(Debug, Deserialize)]
struct HashRequest {
    #[serde(default = "default_hash_alg_name")]
    alg: String,
    content: ContentIn,
}

fn default_hash_alg_name() -> String {
    "streebog256".into()
}

fn handle_hash(rt: Arc<Runtime>, mut request: Request, origin: Option<&str>) -> Result<()> {
    if let Err((code, msg)) = authorize_request(&rt.acl, &request, origin) {
        return auth_err(request, code, msg, origin, &rt.acl);
    }
    let parsed: HashRequest = match read_json(&mut request) {
        Ok(p) => p,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    let (content, digest_in) = match parse_content(&parsed.content) {
        Ok(v) => v,
        Err((c, m)) => return respond_err(request, 400, c, m, origin, &rt.acl),
    };
    if digest_in.is_some() {
        return respond_err(
            request,
            400,
            "invalid_content",
            "hash requires content.b64, not hash_hex",
            origin,
            &rt.acl,
        );
    }
    let content = content.unwrap();
    let oid = match parsed.alg.trim().to_ascii_lowercase().as_str() {
        "streebog256" | "gost2012-256" | "256" => cades::OID_DIGEST_256,
        "streebog512" | "gost2012-512" | "512" => cades::OID_DIGEST_512,
        other => {
            return respond_err(
                request,
                400,
                "invalid_profile",
                format!("unknown alg '{other}' (expected streebog256|streebog512)"),
                origin,
                &rt.acl,
            )
        }
    };
    let digest = cades::digest_by_oid(oid, &content).context("digest")?;
    respond_json_cors(
        request,
        200,
        &json!({
            "digest": {
                "alg": digest_alg_name(oid),
                "hex": hex::encode(&digest),
                "b64": STANDARD.encode(&digest),
            }
        }),
        origin,
        &rt.acl,
    )
}
