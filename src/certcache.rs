// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin
//! Disk-backed cache for container certificate data and OCSP revocation
//! results. Backs `rutoken containers` / `rutoken inspect` so that repeated
//! invocations neither re-read the Rutoken filesystem nor re-query OCSP
//! responders more often than the configured TTL.
use crate::{ocsp, x509};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CACHE_FILE_VERSION: u32 = 1;
/// How long a cached container certificate is trusted before the Rutoken
/// filesystem is read again.
const CONTAINER_TTL_SECS: i64 = 12 * 3_600;
/// TTL for a confirmed Good/Revoked OCSP result.
const REVOCATION_TTL_SECS: i64 = 24 * 3_600;
/// TTL for an Unknown result (no responder, network error, etc.) so a
/// transient failure gets retried sooner than a confirmed status.
const REVOCATION_ERROR_TTL_SECS: i64 = 3_600;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContainerEntry {
    pub uuid: Option<String>,
    pub subject_cn: Option<String>,
    cert_der_b64: String,
    pub fetched_at: i64,
}

impl ContainerEntry {
    pub fn new(
        uuid: Option<String>,
        subject_cn: Option<String>,
        cert_der: &[u8],
        fetched_at: i64,
    ) -> Self {
        Self {
            uuid,
            subject_cn,
            cert_der_b64: STANDARD.encode(cert_der),
            fetched_at,
        }
    }

    pub fn cert_der(&self) -> Result<Vec<u8>> {
        STANDARD
            .decode(&self.cert_der_b64)
            .context("decode cached certificate")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RevocationEntry {
    status: x509::RevocationCheckResult,
    #[allow(dead_code)]
    checked_at: i64,
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct CertCacheFile {
    #[serde(default = "default_version")]
    version: u32,
    #[serde(default)]
    containers: HashMap<String, ContainerEntry>,
    #[serde(default)]
    revocations: HashMap<String, RevocationEntry>,
}

fn default_version() -> u32 {
    CACHE_FILE_VERSION
}

impl Default for CertCacheFile {
    // NB: deriving `Default` here would silently set `version: 0`, which
    // never matches `CACHE_FILE_VERSION` and made `CertCache::load()`
    // discard the on-disk cache on every single invocation — the cache
    // file was rewritten each run but never successfully read back.
    fn default() -> Self {
        Self {
            version: CACHE_FILE_VERSION,
            containers: HashMap::new(),
            revocations: HashMap::new(),
        }
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn cache_path() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("jex")
        .join("cert-cache.json")
}

/// Cache key built solely from the certificate itself (serial number + the
/// issuer Name field already present in the cert). This lets a cache hit
/// short-circuit before ever needing the actual issuer certificate.
fn revocation_key(cert_der: &[u8]) -> Result<String> {
    let names = x509::names(cert_der)?;
    Ok(format!(
        "{}:{}",
        hex::encode(&names.serial_der),
        hex::encode(&names.issuer_der)
    ))
}

pub struct CertCache {
    file: CertCacheFile,
    container_ttl_secs: i64,
}

impl CertCache {
    pub fn load() -> Self {
        let file = std::fs::read(cache_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CertCacheFile>(&bytes).ok())
            .filter(|f| f.version == CACHE_FILE_VERSION)
            .unwrap_or_default();
        Self {
            file,
            container_ttl_secs: CONTAINER_TTL_SECS,
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = cache_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create cache directory {}", dir.display()))?;
        }
        let bytes = serde_json::to_vec_pretty(&self.file).context("serialize certificate cache")?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("write certificate cache {}", path.display()))
    }

    /// Look up a cached container certificate, ignoring entries older than
    /// the container TTL.
    pub fn get_container(&self, key: &str) -> Option<&ContainerEntry> {
        let entry = self.file.containers.get(key)?;
        if now() - entry.fetched_at > self.container_ttl_secs {
            return None;
        }
        Some(entry)
    }

    pub fn put_container(&mut self, key: String, entry: ContainerEntry) {
        self.file.containers.insert(key, entry);
    }

    /// Drop any cached revocation result for `cert_der`, forcing the next
    /// `check_revocation` call to hit the network. Used by `--refresh`.
    pub fn invalidate_revocation(&mut self, cert_der: &[u8]) {
        if let Ok(key) = revocation_key(cert_der) {
            self.file.revocations.remove(&key);
        }
    }

    /// Non-mutating lookup of a still-fresh revocation result, without ever
    /// touching the network. Used for `--offline` mode.
    pub fn peek_revocation(&self, cert_der: &[u8]) -> Option<x509::RevocationCheckResult> {
        let key = revocation_key(cert_der).ok()?;
        let entry = self.file.revocations.get(&key)?;
        if now() >= entry.expires_at {
            return None;
        }
        Some(entry.status.clone())
    }

    /// Check certificate revocation status with disk caching. `resolve_issuer`
    /// is only invoked on a cache miss (it typically performs a network AIA
    /// fetch), keeping cache hits fully offline.
    pub fn check_revocation(
        &mut self,
        cert_der: &[u8],
        resolve_issuer: impl FnOnce() -> Result<Option<Vec<u8>>>,
        ocsp_url: Option<&str>,
        timeout_secs: u64,
    ) -> x509::RevocationCheckResult {
        let key = match revocation_key(cert_der) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("warning: could not derive revocation cache key: {e:#}");
                return x509::RevocationCheckResult::Unknown;
            }
        };
        if let Some(entry) = self.file.revocations.get(&key) {
            if now() < entry.expires_at {
                return entry.status.clone();
            }
        }

        let status = match resolve_issuer() {
            Ok(Some(issuer_der)) => {
                match ocsp::check_status(cert_der, &issuer_der, ocsp_url, timeout_secs) {
                    Ok(ocsp::CertStatusOutcome::Good) => x509::RevocationCheckResult::Good,
                    Ok(ocsp::CertStatusOutcome::Revoked { reason }) => {
                        x509::RevocationCheckResult::Revoked { reason }
                    }
                    Ok(ocsp::CertStatusOutcome::Unknown) => x509::RevocationCheckResult::Unknown,
                    Err(e) => {
                        eprintln!("warning: OCSP check failed: {e:#}");
                        x509::RevocationCheckResult::Unknown
                    }
                }
            }
            // Self-signed root or certificate without an AIA caIssuers URL:
            // there is no issuer to query OCSP against.
            Ok(None) => x509::RevocationCheckResult::Unknown,
            Err(e) => {
                eprintln!("warning: could not obtain issuer certificate: {e:#}");
                x509::RevocationCheckResult::Unknown
            }
        };

        let checked_at = now();
        let ttl = match &status {
            x509::RevocationCheckResult::Good | x509::RevocationCheckResult::Revoked { .. } => {
                REVOCATION_TTL_SECS
            }
            x509::RevocationCheckResult::Unknown => REVOCATION_ERROR_TTL_SECS,
        };
        self.file.revocations.insert(
            key,
            RevocationEntry {
                status: status.clone(),
                checked_at,
                expires_at: checked_at + ttl,
            },
        );
        status
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_entry_ttl_expiry() {
        let expired = RevocationEntry {
            status: x509::RevocationCheckResult::Good,
            checked_at: now() - 100,
            expires_at: now() - 1,
        };
        assert!(now() >= expired.expires_at);
        let fresh = RevocationEntry {
            status: x509::RevocationCheckResult::Good,
            checked_at: now(),
            expires_at: now() + 3600,
        };
        assert!(now() < fresh.expires_at);
    }

    #[test]
    fn cache_file_json_roundtrip() {
        let mut file = CertCacheFile::default();
        file.version = CACHE_FILE_VERSION;
        file.containers.insert(
            "atr:path".to_string(),
            ContainerEntry::new(
                Some("uuid-1".to_string()),
                Some("Test CN".to_string()),
                b"fake-cert-bytes",
                12345,
            ),
        );
        file.revocations.insert(
            "serial:issuer".to_string(),
            RevocationEntry {
                status: x509::RevocationCheckResult::Revoked {
                    reason: Some("keyCompromise".to_string()),
                },
                checked_at: 1,
                expires_at: 2,
            },
        );

        let json = serde_json::to_vec(&file).expect("serialize");
        let restored: CertCacheFile = serde_json::from_slice(&json).expect("deserialize");

        assert_eq!(restored.version, CACHE_FILE_VERSION);
        let entry = restored
            .containers
            .get("atr:path")
            .expect("container entry present");
        assert_eq!(entry.cert_der().unwrap(), b"fake-cert-bytes");
        assert_eq!(entry.subject_cn.as_deref(), Some("Test CN"));
        assert_eq!(
            restored.revocations.get("serial:issuer").unwrap().status,
            x509::RevocationCheckResult::Revoked {
                reason: Some("keyCompromise".to_string())
            }
        );
    }

    #[test]
    fn corrupt_cache_file_falls_back_to_empty() {
        let parsed: Option<CertCacheFile> = serde_json::from_slice(b"not json").ok();
        assert!(parsed.is_none());
    }

    #[test]
    fn cache_survives_a_save_load_roundtrip_through_disk() {
        // Regression test: `CertCacheFile::default()` used to leave
        // `version: 0`, which never matched `CACHE_FILE_VERSION` and made
        // every `CertCache::load()` discard the file that was just written.
        let dir = std::env::temp_dir().join(format!("jex-certcache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cert-cache.json");

        let mut cache = CertCache {
            file: CertCacheFile::default(),
            container_ttl_secs: CONTAINER_TTL_SECS,
        };
        cache.put_container(
            "atr:path".to_string(),
            ContainerEntry::new(Some("uuid-1".to_string()), None, b"fake-cert", now()),
        );
        let bytes = serde_json::to_vec_pretty(&cache.file).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let reloaded = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<CertCacheFile>(&b).ok())
            .filter(|f| f.version == CACHE_FILE_VERSION)
            .expect("cache file must round-trip through the version check");
        assert!(reloaded.containers.contains_key("atr:path"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
