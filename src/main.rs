// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

mod archive;
mod cades;
mod certcache;
mod cms_der;
mod container;
mod cpkdf;
mod curves;
mod daemon;
mod der;
mod gost28147;
mod gost3412;
mod enveloped;
mod gost3410;
mod ocsp;
mod oids;
mod pkix;
mod rutoken;
mod timestamp;
mod tui;
mod validation;
mod verification;
mod x509;
mod xlong;
mod xml_c14n;
mod xml_util;
mod xmldsig;
mod nmcades_host;
mod nmcades_ui;

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use container::ClassicContainer;
use rutoken::RutokenCard;
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

/// Network timeout for OCSP revocation lookups triggered by `rutoken
/// containers` / `rutoken inspect`.
const OCSP_CHECK_TIMEOUT_SECS: u64 = 8;

#[derive(Parser, Debug)]
#[command(
    name = "jex",
    version,
    about = "CryptoPro containers, CAdES and XML-DSig/XAdES"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Containers saved on disk
    Hdimage {
        #[command(subcommand)]
        cmd: HdimageCommand,
    },
    /// Rutoken smart card
    Rutoken {
        #[command(subcommand)]
        cmd: RutokenCommand,
    },
    /// CMS / CAdES signatures
    Cades {
        #[command(subcommand)]
        cmd: CadesCommand,
    },
    /// Encrypt a file (CMS EnvelopedData, GOST + VKO)
    Encrypt {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Output CMS file (.p7e)
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Recipient certificate PEM/DER (repeatable)
        #[arg(long = "recipient-cert", value_name = "FILE", required = true)]
        recipient_cert: Vec<PathBuf>,
        /// Content encryption: gost28147 | magma | kuznyechik (or 25|35|45)
        #[arg(long = "alg", default_value = "gost28147")]
        alg: String,
    },
    /// Decrypt a CMS EnvelopedData file
    Decrypt {
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Output plaintext file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Container directory (repeatable)
        #[arg(long = "container-dir", value_name = "DIR")]
        container_dir: Vec<PathBuf>,
        /// Scan this directory for containers
        #[arg(long = "containers-root", value_name = "DIR", conflicts_with_all = ["reader", "path", "token_pin", "token_pin_file"])]
        containers_root: Option<PathBuf>,
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Container PIN
        #[arg(long, conflicts_with = "container_pin_file")]
        container_pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "container_pin")]
        container_pin_file: Option<PathBuf>,
    },
    /// XML-DSig / XAdES signatures
    Xml {
        #[command(subcommand)]
        cmd: XmlCommand,
    },
    /// Unlock containers and serve signing over HTTP
    Daemon {
        /// JSON config (keys + API key ACL)
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Override listen address from config
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
    /// Chrome Native Messaging host (replace CryptoPro nmcades)
    NmcadesHost {
        /// Same JSON as `jex daemon --config`
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// Override TSA URL from config
        #[arg(long)]
        tsa: Option<String>,
        /// Serve localhost HTTP bridge instead of stdio (Safari)
        #[arg(long, value_name = "ADDR")]
        http: Option<String>,
        /// Chrome passes `chrome-extension://…/` here; ignored.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _chrome_args: Vec<String>,
    },
}
#[derive(Subcommand, Debug)]
enum HdimageCommand {
    /// Show container info
    Inspect { dir: PathBuf },
    /// Unlock the private key
    Unlock {
        dir: PathBuf,
        /// Container PIN
        #[arg(long, conflicts_with = "pin_file")]
        pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "pin")]
        pin_file: Option<PathBuf>,
        /// Write private key to this file
        #[arg(long, value_name = "FILE")]
        out_private: Option<PathBuf>,
    },
    /// Create a new classic container on disk (key only, no certificate)
    Create {
        /// Output directory (created if missing)
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Container PIN
        #[arg(long, conflicts_with = "pin_file")]
        pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "pin")]
        pin_file: Option<PathBuf>,
        /// Container UUID / name.key value (generated if omitted)
        #[arg(long)]
        name: Option<String>,
        /// Curve OID (default: CryptoPro-XchA / 2012-256)
        #[arg(long, default_value = container::DEFAULT_CREATE_CURVE_OID)]
        curve: String,
    },
    /// Build a PKCS#10 certificate request from an existing container
    Request {
        dir: PathBuf,
        /// Container PIN
        #[arg(long, conflicts_with = "pin_file")]
        pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "pin")]
        pin_file: Option<PathBuf>,
        /// Subject CN for the CSR
        #[arg(long, default_value = "Jex")]
        cn: String,
        /// Write CSR DER (or PEM with --pem) here
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Write PEM instead of DER
        #[arg(long)]
        pem: bool,
    },
    /// Install a CA-issued certificate into header.key
    InstallCert {
        dir: PathBuf,
        /// Certificate PEM or DER
        #[arg(long, value_name = "FILE")]
        cert: PathBuf,
        /// Container PIN (optional; enables full pubkey check)
        #[arg(long, conflicts_with = "pin_file")]
        pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "pin")]
        pin_file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum RutokenCommand {
    /// List card readers
    List,
    /// Show card filesystem
    Tree {
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
    },
    /// List containers on the card
    Containers {
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Use cache only, no network
        #[arg(long)]
        offline: bool,
        /// Ignore cache and re-read
        #[arg(long)]
        refresh: bool,
    },
    /// Save container files to disk
    Dump {
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number from `containers`
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Output directory
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Show a container from the card
    Inspect {
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number from `containers`
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Use cache only, no network
        #[arg(long)]
        offline: bool,
        /// Ignore cache and re-read
        #[arg(long)]
        refresh: bool,
    },
    /// Unlock a private key from the card
    Unlock {
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number from `containers`
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Container PIN
        #[arg(long, conflicts_with = "container_pin_file")]
        container_pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "container_pin")]
        container_pin_file: Option<PathBuf>,
        /// Write private key to this file
        #[arg(long, value_name = "FILE")]
        out_private: Option<PathBuf>,
        /// Also save container files here
        #[arg(long, value_name = "DIR")]
        dump_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum CadesCommand {
    /// List containers and certificates
    Certificates {
        /// Container directory (repeatable)
        #[arg(long = "container-dir", value_name = "DIR")]
        container_dir: Vec<PathBuf>,
        /// Scan this directory for containers
        #[arg(long = "containers-root", value_name = "DIR", conflicts_with_all = ["reader", "token_pin", "token_pin_file"])]
        containers_root: Option<PathBuf>,
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
    },
    /// Sign a file
    Sign {
        /// File to sign
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Output signature file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Embed the file in the signature
        #[arg(long)]
        attached: bool,
        /// Soft private key PEM (RSA or P-256 PKCS#8 / PKCS#1 / SEC1)
        #[arg(
            long = "key-pem",
            value_name = "FILE",
            conflicts_with_all = [
                "container_dir",
                "containers_root",
                "reader",
                "path",
                "index",
                "token_pin",
                "token_pin_file",
                "container_pin",
                "container_pin_file",
            ]
        )]
        key_pem: Option<PathBuf>,
        /// Signer certificate PEM/DER (required with --key-pem)
        #[arg(long, value_name = "FILE", requires = "key_pem")]
        cert: Option<PathBuf>,
        /// Container directory (repeatable)
        #[arg(long = "container-dir", value_name = "DIR")]
        container_dir: Vec<PathBuf>,
        /// Scan this directory for containers
        #[arg(long = "containers-root", value_name = "DIR", conflicts_with_all = ["reader", "path", "token_pin", "token_pin_file"])]
        containers_root: Option<PathBuf>,
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Container PIN
        #[arg(long, conflicts_with = "container_pin_file")]
        container_pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "container_pin")]
        container_pin_file: Option<PathBuf>,
        /// Timestamp server URL
        #[arg(long, value_name = "URL")]
        tsa: Option<String>,
        /// Timestamp policy OID
        #[arg(long, value_name = "OID", requires = "tsa")]
        tsa_policy: Option<String>,
        /// Timestamp request timeout (seconds)
        #[arg(long, default_value_t = 20, requires = "tsa")]
        tsa_timeout_secs: u64,
        /// Allow signing with an expired certificate
        #[arg(long)]
        allow_expired_certificate: bool,
        /// Show technical verification dump (alias: --detail)
        #[arg(long, visible_alias = "detail")]
        verbose: bool,
    },
    /// Add chain and revocation data (X Long Type 1)
    Enhance {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Output signature file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Timestamp server URL
        #[arg(long, value_name = "URL")]
        tsa: String,
        /// Timestamp policy OID
        #[arg(long, value_name = "OID")]
        tsa_policy: Option<String>,
        /// Timestamp request timeout (seconds)
        #[arg(long, default_value_t = 20)]
        tsa_timeout_secs: u64,
        /// CA certificate (repeat: issuer first, root last)
        #[arg(long = "chain-cert", value_name = "FILE")]
        chain_cert: Vec<PathBuf>,
        /// Revocation list file (repeatable)
        #[arg(long = "crl", value_name = "FILE")]
        crl: Vec<PathBuf>,
        /// Saved revocation response for the signer
        #[arg(long = "ocsp-file", value_name = "FILE", conflicts_with = "ocsp_url")]
        ocsp_file: Option<PathBuf>,
        /// Revocation service URL
        #[arg(long = "ocsp-url", value_name = "URL", conflicts_with = "ocsp_file")]
        ocsp_url: Option<String>,
        /// Do not download missing certificates or revocation data
        #[arg(long)]
        no_fetch_validation: bool,
        /// Network timeout (seconds)
        #[arg(long, default_value_t = 20)]
        fetch_timeout_secs: u64,
    },
    /// Add or renew an archive timestamp
    Archive {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Original signed file (needed if signature is detached)
        #[arg(long, value_name = "FILE", conflicts_with = "content_hash")]
        content: Option<PathBuf>,
        /// Hex digest of the signed file (SignerInfo.digestAlgorithm = messageDigest).
        /// Enough for detached CAdES-A: ATSv3 only embeds H(content).
        #[arg(long = "content-hash", value_name = "HEX", conflicts_with = "content")]
        content_hash: Option<String>,
        /// Output signature file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Timestamp server URL
        #[arg(long, value_name = "URL")]
        tsa: String,
        /// Timestamp policy OID
        #[arg(long, value_name = "OID")]
        tsa_policy: Option<String>,
        /// Timestamp request timeout (seconds)
        #[arg(long, default_value_t = 20)]
        tsa_timeout_secs: u64,
        /// Network timeout (seconds)
        #[arg(long, default_value_t = 20)]
        fetch_timeout_secs: u64,
    },
    /// Embed the signed file into a detached signature
    Attach {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Original signed file to embed
        #[arg(long, value_name = "FILE")]
        content: PathBuf,
        /// Output signature file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Strip embedded content from an attached signature
    Detach {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Output detached signature file
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Write the extracted original content here
        #[arg(long = "content-out", value_name = "FILE")]
        content_out: Option<PathBuf>,
    },
    /// Check signature completeness
    Audit {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Original signed file (needed if signature is detached)
        #[arg(long, value_name = "FILE", conflicts_with = "content_hash")]
        content: Option<PathBuf>,
        /// Hex digest of the signed file (alternative to --content for CAdES-A)
        #[arg(long = "content-hash", value_name = "HEX", conflicts_with = "content")]
        content_hash: Option<String>,
    },
    /// Show signature structure
    Inspect {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
    },
    /// Verify a signature
    Verify {
        #[arg(value_name = "SIGNATURE")]
        signature: PathBuf,
        /// Original signed file (needed if signature is detached)
        #[arg(long, value_name = "FILE", conflicts_with = "content_hash")]
        content: Option<PathBuf>,
        /// Hex digest of the signed file (checks messageDigest; CAdES-A ATSv3 ok)
        #[arg(long = "content-hash", value_name = "HEX", conflicts_with = "content")]
        content_hash: Option<String>,
        /// Use cache only, no network
        #[arg(long)]
        offline: bool,
        /// Ignore cache and re-check
        #[arg(long)]
        refresh: bool,
        /// Network timeout (seconds)
        #[arg(long, default_value_t = OCSP_CHECK_TIMEOUT_SECS)]
        fetch_timeout_secs: u64,
        /// Show technical verification dump (alias: --detail)
        #[arg(long, visible_alias = "detail")]
        verbose: bool,
    },
}

#[derive(Subcommand, Debug)]
enum XmlCommand {
    /// Sign an XML document (XML-DSig / XAdES)
    Sign {
        /// XML file to sign
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Output signed XML
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Packaging: enveloped | enveloping | template
        #[arg(long, default_value = "enveloped")]
        r#type: String,
        /// Profile: xmldsig | bes | t | xlt1 | a
        #[arg(long, default_value = "bes")]
        profile: String,
        /// Container directory (repeatable)
        #[arg(long = "container-dir", value_name = "DIR")]
        container_dir: Vec<PathBuf>,
        /// Scan this directory for containers
        #[arg(long = "containers-root", value_name = "DIR", conflicts_with_all = ["reader", "path", "token_pin", "token_pin_file"])]
        containers_root: Option<PathBuf>,
        /// Reader name substring
        #[arg(long, value_name = "SUBSTRING")]
        reader: Option<String>,
        /// Path on card, e.g. 0A00/EFA7
        #[arg(long, value_name = "FID/FID")]
        path: Option<String>,
        /// Container number
        #[arg(long)]
        index: Option<usize>,
        /// Max search depth
        #[arg(long, default_value_t = 3)]
        max_depth: usize,
        /// Card PIN
        #[arg(long, conflicts_with = "token_pin_file")]
        token_pin: Option<String>,
        /// File with card PIN
        #[arg(long, value_name = "FILE", conflicts_with = "token_pin")]
        token_pin_file: Option<PathBuf>,
        /// Container PIN
        #[arg(long, conflicts_with = "container_pin_file")]
        container_pin: Option<String>,
        /// File with container PIN
        #[arg(long, value_name = "FILE", conflicts_with = "container_pin")]
        container_pin_file: Option<PathBuf>,
        /// Timestamp server URL (required for profile t / xlt1 / a)
        #[arg(long)]
        tsa: Option<String>,
        /// TSA policy OID
        #[arg(long)]
        tsa_policy: Option<String>,
        /// TSA HTTP timeout (seconds)
        #[arg(long, default_value_t = 20)]
        tsa_timeout_secs: u64,
        /// XPath for template signing
        #[arg(long)]
        xpath: Option<String>,
        /// Allow expired signer certificate
        #[arg(long)]
        allow_expired_certificate: bool,
        /// Extra details
        #[arg(long, visible_alias = "detail")]
        verbose: bool,
    },
    /// Verify a signed XML document
    Verify {
        /// Signed XML file
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// XPath selecting the Signature (optional)
        #[arg(long)]
        xpath: Option<String>,
        /// Extra details
        #[arg(long, visible_alias = "detail")]
        verbose: bool,
    },
    /// Add or renew XAdES ArchiveTimeStamp (XAdES-A)
    Archive {
        /// Existing XAdES-XLT1/A signed XML
        #[arg(value_name = "FILE")]
        input: PathBuf,
        /// Output signed XML
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        /// Timestamp server URL
        #[arg(long)]
        tsa: String,
        /// TSA policy OID
        #[arg(long)]
        tsa_policy: Option<String>,
        /// TSA HTTP timeout (seconds)
        #[arg(long, default_value_t = 20)]
        tsa_timeout_secs: u64,
        /// Signature Id (default: first ds:Signature)
        #[arg(long)]
        signature_id: Option<String>,
    },
    /// Show SignedXML / XAdES structure
    Inspect {
        /// Signed XML file
        #[arg(value_name = "FILE")]
        input: PathBuf,
    },
}

fn read_optional_secret(
    value: Option<String>,
    file: Option<PathBuf>,
    what: &str,
) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>> {
    if let Some(value) = value {
        return Ok(Some(zeroize::Zeroizing::new(value.into_bytes())));
    }
    if let Some(path) = file {
        let mut data = zeroize::Zeroizing::new(
            fs::read(&path).with_context(|| format!("read {what} file {}", path.display()))?,
        );
        while data.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            data.pop();
        }
        return Ok(Some(data));
    }
    Ok(None)
}

fn parse_content_hash_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let bytes = hex::decode(&cleaned).context("invalid --content-hash HEX")?;
    if bytes.len() != 32 && bytes.len() != 64 {
        anyhow::bail!(
            "--content-hash must be 32 bytes (Streebog-256) or 64 bytes (Streebog-512), got {}",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn read_container_pin(
    value: Option<String>,
    file: Option<PathBuf>,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    Ok(read_optional_secret(value, file, "container PIN")?.unwrap_or_default())
}

fn format_container_name(c: &ClassicContainer) -> String {
    if let Some(name) = c.name.as_deref() {
        return name.to_string();
    }
    if let Some(name_bytes) = c.files.name.as_deref() {
        return container::parse_name_or_hex(name_bytes);
    }
    "<absent>".to_string()
}

fn print_container(c: &ClassicContainer, source: &str) {
    println!("source: {source}");
    let name = format_container_name(c);
    println!("name: {name}");
    if let Some(uuid) = &c.uuid {
        println!("uuid: {uuid}");
    }
    println!("curve: {} ({})", c.curve.name, c.curve.oid);
    println!("private size: {} bits", c.curve.bytes * 8);

    match c.certificate.as_deref() {
        Some(cert) => {
            println!("certificate: {} bytes", cert.len());
            if let Ok(cn) = x509::extract_subject_cn(cert) {
                if let Some(cn_value) = cn {
                    println!("  subject CN: {cn_value}");
                }
            }
            if let Ok(validity) = x509::validity(cert) {
                println!(
                    "  validity: {} to {}",
                    validity.not_before, validity.not_after
                );
            }
        }
        None => println!("certificate: <not found>"),
    }

    match c.primary_fp {
        Some(fp) => println!("primaryFP: {}", hex::encode(fp)),
        None => println!("primaryFP: <not found>"),
    }
    println!("OIDs:");
    for oid in &c.oids {
        match oids::describe(oid) {
            Some(label) => println!("  {oid}  {label}"),
            None => println!("  {oid}"),
        }
    }
}

fn print_unlocked(
    c: &ClassicContainer,
    mut key: container::UnlockedKey,
    out_private: Option<PathBuf>,
) -> Result<()> {
    println!("verified: yes (primaryFP)");
    println!(
        "key pair: {}",
        if key.used_backup {
            "masks2.key + primary2.key"
        } else {
            "masks.key + primary.key"
        }
    );
    println!("curve: {}", c.curve.name);
    println!("public X (LE): {}", hex::encode(&key.public_x_le));
    println!("public Y (LE): {}", hex::encode(&key.public_y_le));

    if let Some(path) = out_private {
        fs::write(&path, &key.private_le)
            .with_context(|| format!("write private key {}", path.display()))?;
        println!("private scalar (LE) written to {}", path.display());
    } else {
        println!("private scalar was NOT printed; use --out-private FILE to export it explicitly");
    }
    key.private_le.zeroize();
    Ok(())
}

fn open_card(reader: Option<&str>) -> Result<RutokenCard> {
    let card = RutokenCard::connect(reader)?;
    println!("reader: {}", card.reader_name);
    if !card.atr.is_empty() {
        println!("ATR: {}", hex::encode_upper(&card.atr));
    }
    Ok(card)
}

fn parse_optional_path(path: Option<String>) -> Result<Option<Vec<u16>>> {
    path.map(|s| rutoken::parse_path(&s)).transpose()
}

fn resolve_image_dirs(
    container_dir: &[PathBuf],
    containers_root: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut dirs = container_dir.to_vec();
    if let Some(root) = containers_root {
        dirs.extend(container::discover_dump_dirs(root)?);
    }
    Ok(dirs)
}

fn open_classic_container(
    image_dirs: &[PathBuf],
    index: Option<usize>,
    reader: Option<&str>,
    path: Option<Vec<u16>>,
    max_depth: usize,
    mut token_pin: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<(ClassicContainer, String)> {
    if !image_dirs.is_empty() {
        let idx = index.unwrap_or(0);
        let dir = image_dirs.get(idx).with_context(|| {
            format!(
                "container index {idx} out of range ({} dumped container dir(s) supplied)",
                image_dirs.len()
            )
        })?;
        let c = ClassicContainer::open(dir)?;
        return Ok((c, dir.display().to_string()));
    }

    let card = open_card(reader)?;
    let selected = card.select_container(path.as_deref(), index, max_depth, token_pin.as_ref().map(|p| p.as_slice()));
    if let Some(pin) = token_pin.as_mut() {
        pin.zeroize();
    }
    let (location, files) = selected?;
    let source = format!("Rutoken {} / {}", card.reader_name, location.display_path());
    Ok((ClassicContainer::from_files(files)?, source))
}

fn print_container_certificate(index: usize, source: &str, c: &ClassicContainer, now: i64) {
    match c.certificate.as_deref() {
        Some(cert) => {
            let cn = x509::extract_subject_cn(cert)
                .ok()
                .flatten()
                .unwrap_or_default();
            let cn_display = if cn.is_empty() {
                String::new()
            } else {
                format!(" CN=\"{}\"", cn)
            };

            match x509::validity(cert) {
                Ok(v) => println!(
                    "[{index}] {source}{cn_display}  cert={}..{}  {}",
                    v.not_before,
                    v.not_after,
                    if v.is_valid_at(now) {
                        "CURRENT"
                    } else {
                        "expired/not-yet-valid"
                    }
                ),
                Err(e) => println!("[{index}] {source}  certificate validity parse error: {e}"),
            }
        }
        None => println!("[{index}] {source}  certificate: not found"),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Stable key identifying a container slot on a physical token, used to
/// index the on-disk certificate cache without depending on live token I/O.
fn container_cache_key(card: &RutokenCard, path: &[u16]) -> String {
    let token_id = if card.atr.is_empty() {
        card.reader_name.clone()
    } else {
        hex::encode(&card.atr)
    };
    format!("{token_id}:{}", rutoken::format_path(path))
}

/// Card-derived data for one container row, collected while the token
/// connection is still open. Revocation checking (network) happens later,
/// once the connection has been released; see `RutokenCommand::Containers`.
struct PendingContainerRow {
    index: usize,
    uuid: Option<String>,
    subject_cn: Option<String>,
    cert_der: Option<Vec<u8>>,
}

fn color_enabled() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn paint(text: &str, color: Option<&str>) -> String {
    match color {
        Some(code) if color_enabled() => format!("\x1b[{code}m{text}\x1b[0m"),
        _ => text.to_string(),
    }
}

fn println_status(label: &str, value: &str, ok: Option<bool>) {
    let color = match ok {
        Some(true) => Some("32"),  // green
        Some(false) => Some("31"), // red
        None => None,
    };
    println!("{label}: {}", paint(value, color));
}

/// Preferred subject fields after the display name (CN / SN+GN).
const SIGNER_EXTRA_LABELS: &[&str] = &[
    "SN", "GN", "O", "OU", "T", "INN", "INNLE", "OGRN", "OGRNIP", "SNILS", "email", "C", "ST", "L",
];

fn format_attr_line(attrs: &[x509::NameAttr], skip_oids: &[&str]) -> Option<String> {
    let mut parts = Vec::new();
    for label in SIGNER_EXTRA_LABELS {
        if let Some(a) = attrs.iter().find(|a| a.label == *label) {
            if skip_oids.contains(&a.oid.as_str()) {
                continue;
            }
            // SN/GN already folded into the display name when CN is absent;
            // still show them when CN is present (common for Russian personal certs).
            parts.push(format!("{}={}", a.label, a.value));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("  "))
    }
}

/// Bit length of an unsigned big-endian RSA modulus (leading zero bytes ignored).
fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    match modulus.iter().position(|&b| b != 0) {
        Some(i) => (modulus.len() - i) * 8 - modulus[i].leading_zeros() as usize,
        None => 0,
    }
}

fn print_signer_identity(cert: &[u8]) {
    let subject = x509::subject_name_attributes(cert).unwrap_or_default();
    let issuer = x509::issuer_name_attributes(cert).unwrap_or_default();
    let display = x509::display_name_from_attrs(&subject).unwrap_or_else(|| "<unknown>".into());
    println!("signer: {}", paint(&display, Some("1;36"))); // bold cyan
    if let Some(line) = format_attr_line(&subject, &["2.5.4.3"]) {
        println!("  {line}");
    }
    let issuer_name = x509::display_name_from_attrs(&issuer).unwrap_or_else(|| "<unknown>".into());
    println!("issuer: {issuer_name}");
    if let Some(line) = format_attr_line(&issuer, &["2.5.4.3"]) {
        // Keep issuer secondary fields quieter — only Russian registry ids + email.
        let quiet: Vec<&str> = line
            .split("  ")
            .filter(|p| {
                p.starts_with("INN=")
                    || p.starts_with("INNLE=")
                    || p.starts_with("OGRN=")
                    || p.starts_with("OGRNIP=")
                    || p.starts_with("email=")
            })
            .collect();
        if !quiet.is_empty() {
            println!("  {}", quiet.join("  "));
        }
    }
}

fn print_signer_validity(validity: &x509::CertValidity, now: i64) {
    let current = validity.is_valid_at(now);
    let status = if current { "current" } else { "NOT CURRENT" };
    let value = format!(
        "{} .. {} ({status})",
        validity.not_before, validity.not_after
    );
    println_status("validity", &value, Some(current));
}

fn print_signer_revocation(status: Option<&x509::RevocationCheckResult>, date_ok: bool) {
    let (text, ok) = if !date_ok {
        ("skipped (certificate not current)".to_string(), None)
    } else {
        match status {
            Some(s @ x509::RevocationCheckResult::Good) => (s.label(), Some(true)),
            Some(s @ x509::RevocationCheckResult::Revoked { .. }) => (s.label(), Some(false)),
            Some(s @ x509::RevocationCheckResult::Unknown) => (s.label(), None),
            None => ("NOT CHECKED".to_string(), None),
        }
    };
    let color = match ok {
        Some(true) => Some("32"),
        Some(false) => Some("31"),
        None => Some("33"), // yellow for unknown / skipped
    };
    println!("revocation: {}", paint(&text, color));
}

fn print_ok_fail(ok: bool) {
    let label = if ok { "OK" } else { "FAIL" };
    println!("{}", paint(label, Some(if ok { "1;32" } else { "1;31" })));
    let _ = io::stdout().flush();
}

fn print_local_verification(report: &verification::LocalVerification) {
    let r = &report.base;
    println!("profile: {}", report.profile.as_str());
    println!("mode: {}", if r.detached { "detached" } else { "attached" });
    println!("digestAlgorithm: {}", r.digest_oid);
    println!("signatureAlgorithm: {}", r.signature_oid);
    println!("curve: {}", r.curve_oid);
    println!(
        "messageDigest: {}",
        if r.message_digest_valid {
            "valid"
        } else {
            "INVALID"
        }
    );
    println!(
        "signingCertificateV2: {}",
        if r.signing_certificate_v2_valid {
            "valid"
        } else {
            "INVALID/MISSING"
        }
    );
    println!(
        "SignerIdentifier: {}",
        if r.signer_id_matches_certificate {
            "matches certificate"
        } else {
            "MISMATCH"
        }
    );
    println!(
        "GOST signature: {}",
        if r.signature_valid {
            "valid"
        } else {
            "INVALID"
        }
    );

    match r.timestamp_imprint_valid {
        Some(ok) => {
            println!(
                "signatureTimeStampToken imprint: {}",
                if ok { "valid" } else { "INVALID" }
            );
            println!(
                "signatureTimeStampToken CMS signature: {}",
                if r.timestamp_token_signature_valid == Some(true) {
                    "valid"
                } else {
                    "INVALID"
                }
            );
            println!(
                "signatureTimeStampToken signer cert at genTime: {}",
                if r.timestamp_token_certificate_valid_at_gen_time == Some(true) {
                    "valid"
                } else {
                    "INVALID"
                }
            );
            if let Some(t) = &r.timestamp_gen_time {
                println!("signature timestamp genTime: {t}");
            }
        }
        None => println!("signatureTimeStampToken: absent"),
    }

    if report.partial_xlong {
        println!("XLT1 structure: INVALID — incomplete CAdES-X Long Type 1 attribute set");
    }
    if let Some(audit) = &report.xlong_audit {
        println!("XLT1 semantic verification:");
        for c in &audit.checks {
            println!(
                "  {}: {} — {}",
                c.name,
                if c.ok { "OK" } else { "FAIL" },
                c.detail
            );
        }
        println!(
            "  result: {}",
            if audit.is_conformant() {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
    if let Some(audit) = &report.archive_audit {
        println!(
            "CAdES-A archive verification ({} archive timestamp(s)):",
            report.archive_count
        );
        for c in &audit.checks {
            println!(
                "  {}: {} — {}",
                c.name,
                if c.ok { "OK" } else { "FAIL" },
                c.detail
            );
        }
        println!(
            "  result: {}",
            if audit.is_conformant() {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
    println!(
        "local verification: {}",
        if report.is_valid() { "PASS" } else { "FAIL" }
    );
}

fn print_pki_verification(pki: &validation::PkiVerification, now: i64) {
    let v = &pki.cert_check.validity;
    println!(
        "signer certificate validity: {} .. {} ({})",
        v.not_before,
        v.not_after,
        if v.is_valid_at(now) {
            "current"
        } else {
            "NOT CURRENT"
        }
    );
    match &pki.cert_check.revocation_status {
        Some(status) => println!("signer certificate revocation: {}", status.label()),
        None if !v.is_valid_at(now) => {
            println!("signer certificate revocation: skipped (certificate not current)")
        }
        None => println!("signer certificate revocation: NOT CHECKED"),
    }
    if pki.chain_depth == 0 {
        println!("certificate chain: self-signed signer");
    } else {
        println!(
            "certificate chain: {} CA certificate(s), signatures valid",
            pki.chain_depth
        );
    }
    println!(
        "PKI validation: {}",
        if pki.is_valid(now) { "PASS" } else { "FAIL" }
    );
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Hdimage { cmd } => match cmd {
            HdimageCommand::Inspect { dir } => {
                let c = ClassicContainer::open(&dir)?;
                print_container(&c, &dir.display().to_string());
            }
            HdimageCommand::Unlock {
                dir,
                pin,
                pin_file,
                out_private,
            } => {
                let c = ClassicContainer::open(&dir)?;
                let mut pin = read_container_pin(pin, pin_file)?;
                let result = c.unlock(&pin);
                pin.zeroize();
                print_unlocked(&c, result?, out_private)?;
            }
            HdimageCommand::Create {
                out,
                pin,
                pin_file,
                name,
                curve,
            } => {
                let mut pin = read_container_pin(pin, pin_file)?;
                let created = container::create_container(&container::CreateContainerParams {
                    pin: &pin,
                    name: name.as_deref(),
                    curve_oid: &curve,
                    not_after_unix: None,
                })?;
                pin.zeroize();
                created.files.write_dir(&out)?;
                println!("created: {}", out.display());
                println!("uuid: {}", created.uuid);
                println!("curve: {} ({})", created.curve_oid, {
                    curves::by_oid(&created.curve_oid)
                        .map(|c| c.name)
                        .unwrap_or("?")
                });
                println!(
                    "public X (LE): {}",
                    hex::encode(&created.public_x_le)
                );
                println!("certificate: (none — use hdimage install-cert after CA issuance)");
            }
            HdimageCommand::Request {
                dir,
                pin,
                pin_file,
                cn,
                out,
                pem,
            } => {
                let c = ClassicContainer::open(&dir)?;
                let mut pin = read_container_pin(pin, pin_file)?;
                let mut key = c.unlock(&pin)?;
                pin.zeroize();
                let csr = container::build_certificate_request(
                    &c.curve,
                    &key.private_le,
                    &key.public_x_le,
                    &key.public_y_le,
                    &cn,
                )?;
                key.private_le.zeroize();
                if pem {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&csr);
                    let mut body = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
                    for chunk in b64.as_bytes().chunks(64) {
                        body.push_str(std::str::from_utf8(chunk).unwrap());
                        body.push('\n');
                    }
                    body.push_str("-----END CERTIFICATE REQUEST-----\n");
                    fs::write(&out, body)
                        .with_context(|| format!("write CSR {}", out.display()))?;
                } else {
                    fs::write(&out, &csr)
                        .with_context(|| format!("write CSR {}", out.display()))?;
                }
                println!("wrote CSR ({} bytes) to {}", csr.len(), out.display());
            }
            HdimageCommand::InstallCert {
                dir,
                cert,
                pin,
                pin_file,
            } => {
                let cert_der = container::read_certificate_file(&cert)?;
                let mut files = container::ContainerFiles::open_dir(&dir)?;
                let pin_bytes = match (pin, pin_file) {
                    (None, None) => None,
                    (p, f) => Some(read_container_pin(p, f)?),
                };
                let result = container::install_certificate(
                    &mut files,
                    &cert_der,
                    pin_bytes.as_ref().map(|p| p.as_slice()),
                );
                if let Some(mut p) = pin_bytes {
                    p.zeroize();
                }
                result?;
                files.write_dir(&dir)?;
                let c = ClassicContainer::open(&dir)?;
                println!("installed certificate into {}", dir.display());
                if let Some(cert) = &c.certificate {
                    if let Ok(Some(cn)) = x509::extract_subject_cn(cert) {
                        println!("subject CN: {cn}");
                    }
                }
            }
        },
        Command::Rutoken { cmd } => match cmd {
            RutokenCommand::List => {
                let readers = rutoken::list_readers()?;
                if readers.is_empty() {
                    println!("no PC/SC readers found");
                }
                for (i, reader) in readers.iter().enumerate() {
                    println!("[{i}] {reader}");
                }
            }
            RutokenCommand::Tree { reader, max_depth } => {
                let card = open_card(reader.as_deref())?;
                let tree = card.tree(max_depth)?;
                if tree.is_empty() {
                    println!("filesystem enumeration returned no children");
                }
                for e in tree {
                    let indent = "  ".repeat(e.path.len().saturating_sub(1));
                    let name = rutoken::classic_ef_name_at_path(&e.path);
                    let size = e.size.map(|s| format!(" {s} bytes")).unwrap_or_default();
                    let known = name.map(|s| format!(" [{s}]")).unwrap_or_default();
                    let acl = if e.kind == rutoken::FileKind::Elementary {
                        format!(
                            " read={} acl={}",
                            e.read_access.label(),
                            if e.sec_attr.is_empty() {
                                "-".into()
                            } else {
                                hex::encode_upper(&e.sec_attr)
                            }
                        )
                    } else {
                        String::new()
                    };
                    println!(
                        "{indent}{} {}{size}{known}{acl}",
                        e.kind.label(),
                        rutoken::format_path(&e.path)
                    );
                }
            }
            RutokenCommand::Containers {
                reader,
                max_depth,
                offline,
                refresh,
            } => {
                let card = open_card(reader.as_deref())?;
                let containers = card.discover_classic_containers(max_depth)?;
                let mut cache = certcache::CertCache::load();
                let now = unix_now();

                // Phase 1: all Rutoken I/O happens here, with the token connection
                // held open as briefly as possible. Revocation checks (network)
                // are deliberately deferred to phase 2, after the token
                // connection below is released, so a slow/unreachable OCSP
                // responder can never leave a PC/SC session idle mid-transaction.
                let mut pending = Vec::with_capacity(containers.len());
                for (i, c) in containers.iter().enumerate() {
                    let cache_key = container_cache_key(&card, &c.path);
                    let mut uuid = None;
                    let mut subject_cn = None;
                    let mut cert_der: Option<Vec<u8>> = None;

                    if !refresh {
                        if let Some(entry) = cache.get_container(&cache_key) {
                            uuid = entry.uuid.clone();
                            subject_cn = entry.subject_cn.clone();
                            cert_der = entry.cert_der().ok();
                        }
                    }

                    if cert_der.is_none() {
                        // name.key and header.key are both readable without a PIN;
                        // that is all `containers` needs — never touch masks/primary.
                        let name = card
                            .try_read_container_name_best_effort(&c.path)
                            .ok()
                            .flatten()
                            .and_then(|bytes| container::parse_name(&bytes));
                        if let Ok(Some(header)) =
                            card.try_read_container_header_best_effort(&c.path)
                        {
                            uuid = container::resolve_uuid(name.as_deref(), &header);
                            if let Some(cert) = x509::find_certificate(&header) {
                                subject_cn = x509::extract_subject_cn(&cert).ok().flatten();
                                cache.put_container(
                                    cache_key,
                                    certcache::ContainerEntry::new(
                                        uuid.clone(),
                                        subject_cn.clone(),
                                        &cert,
                                        now,
                                    ),
                                );
                                cert_der = Some(cert);
                            }
                        }
                    }

                    pending.push(PendingContainerRow {
                        index: i,
                        uuid,
                        subject_cn,
                        cert_der,
                    });
                }
                drop(card); // release the token connection before any network I/O

                // Phase 2: revocation checks, cached to disk with a TTL so
                // repeat invocations do not need the network either.
                let mut rows = Vec::with_capacity(pending.len());
                for p in pending {
                    if refresh {
                        if let Some(cert) = p.cert_der.as_deref() {
                            cache.invalidate_revocation(cert);
                        }
                    }
                    let check = p.cert_der.as_deref().map(|cert| {
                        validation::check_certificate(
                            cert,
                            None,
                            OCSP_CHECK_TIMEOUT_SECS,
                            &mut cache,
                            !offline,
                            now,
                        )
                    });
                    rows.push(tui::ContainerRow {
                        index: p.index,
                        uuid: p.uuid,
                        subject_cn: p.subject_cn,
                        check,
                    });
                }

                if let Err(e) = cache.save() {
                    eprintln!("warning: could not persist certificate cache: {e:#}");
                }

                tui::run_containers_table(&rows, now)?;
            }
            RutokenCommand::Dump {
                reader,
                path,
                index,
                max_depth,
                token_pin,
                token_pin_file,
                out,
            } => {
                let card = open_card(reader.as_deref())?;
                let path = parse_optional_path(path)?;
                let mut token_pin = read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?;
                let selected =
                    card.select_container(path.as_deref(), index, max_depth, token_pin.as_ref().map(|p| p.as_slice()));
                if let Some(pin) = token_pin.as_mut() {
                    pin.zeroize();
                }
                let (location, files) = selected?;
                files.write_dir(&out)?;
                println!("container: {}", location.display_path());
                println!("saved to: {}", out.display());
            }
            RutokenCommand::Inspect {
                reader,
                path,
                index,
                max_depth,
                token_pin,
                token_pin_file,
                offline,
                refresh,
            } => {
                let card = open_card(reader.as_deref())?;
                let cli_path = parse_optional_path(path)?;
                let mut token_pin = read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?;
                let selected = card.select_container(
                    cli_path.as_deref(),
                    index,
                    max_depth,
                    token_pin.as_ref().map(|p| p.as_slice()),
                );
                if let Some(pin) = token_pin.as_mut() {
                    pin.zeroize();
                }
                let (location, files) = selected?;
                let c = ClassicContainer::from_files(files)?;

                let cache_key = container_cache_key(&card, &location.path);
                let source = format!("Rutoken {} / {}", card.reader_name, location.display_path());
                drop(card); // release the token connection before any network I/O

                let mut cache = certcache::CertCache::load();
                let now = unix_now();
                if let Some(cert) = c.certificate.as_deref() {
                    cache.put_container(
                        cache_key,
                        certcache::ContainerEntry::new(
                            c.uuid.clone(),
                            x509::extract_subject_cn(cert).ok().flatten(),
                            cert,
                            now,
                        ),
                    );
                    if refresh {
                        cache.invalidate_revocation(cert);
                    }
                }
                let check = c.certificate.as_deref().map(|cert| {
                    validation::check_certificate(
                        cert,
                        None,
                        OCSP_CHECK_TIMEOUT_SECS,
                        &mut cache,
                        !offline,
                        now,
                    )
                });
                if let Err(e) = cache.save() {
                    eprintln!("warning: could not persist certificate cache: {e:#}");
                }

                tui::run_container_details(&c, &source, check.as_ref(), now)?;
            }
            RutokenCommand::Unlock {
                reader,
                path,
                index,
                max_depth,
                token_pin,
                token_pin_file,
                container_pin,
                container_pin_file,
                out_private,
                dump_dir,
            } => {
                let card = open_card(reader.as_deref())?;
                let path = parse_optional_path(path)?;
                let mut token_pin = read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?;
                let selected =
                    card.select_container(path.as_deref(), index, max_depth, token_pin.as_ref().map(|p| p.as_slice()));
                if let Some(pin) = token_pin.as_mut() {
                    pin.zeroize();
                }
                let (location, files) = selected?;

                if let Some(dir) = &dump_dir {
                    files.write_dir(dir)?;
                    println!("encrypted container dumped to {}", dir.display());
                }

                let c = ClassicContainer::from_files(files)?;
                print_container(
                    &c,
                    &format!("Rutoken {} / {}", card.reader_name, location.display_path()),
                );

                let mut pin = read_container_pin(container_pin, container_pin_file)?;
                let unlocked = c.unlock(&pin);
                pin.zeroize();
                print_unlocked(&c, unlocked?, out_private)?;
            }
        },
        Command::Cades { cmd } => match cmd {
            CadesCommand::Certificates {
                container_dir,
                containers_root,
                reader,
                max_depth,
                token_pin,
                token_pin_file,
            } => {
                let image_dirs = resolve_image_dirs(&container_dir, containers_root.as_deref())?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .context("system clock is before Unix epoch")?
                    .as_secs() as i64;

                if !image_dirs.is_empty() {
                    println!("containers: {}", image_dirs.len());
                    for (i, dir) in image_dirs.iter().enumerate() {
                        match ClassicContainer::open(dir) {
                            Ok(c) => {
                                print_container_certificate(i, &dir.display().to_string(), &c, now)
                            }
                            Err(e) => println!("[{i}] {}  unreadable: {e}", dir.display()),
                        }
                    }
                } else {
                    let card = open_card(reader.as_deref())?;
                    let locations = card.discover_classic_containers(max_depth)?;
                    let mut token_pin =
                        read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?;
                    println!("containers: {}", locations.len());
                    for (i, location) in locations.iter().enumerate() {
                        let source = location.display_path();
                        match card
                            .read_classic_container(&location.path, token_pin.as_ref().map(|p| p.as_slice()))
                            .and_then(ClassicContainer::from_files)
                        {
                            Ok(c) => print_container_certificate(i, &source, &c, now),
                            Err(e) => println!("[{i}] {source}  unreadable: {e}"),
                        }
                    }
                    if let Some(pin) = token_pin.as_mut() {
                        pin.zeroize();
                    }
                }
            }
            CadesCommand::Sign {
                input,
                out,
                attached,
                key_pem,
                cert,
                container_dir,
                containers_root,
                reader,
                path,
                index,
                max_depth,
                token_pin,
                token_pin_file,
                container_pin,
                container_pin_file,
                tsa,
                tsa_policy,
                tsa_timeout_secs,
                allow_expired_certificate,
                verbose,
            } => {
                let outcome = (|| -> Result<()> {
                    let content = fs::read(&input)
                        .with_context(|| format!("read content {}", input.display()))?;

                    let (signed, source, key_line, digest_oid_for_tsa) = if let Some(key_path) = key_pem.as_ref()
                    {
                        let cert_path = cert.as_ref().context("--cert is required with --key-pem")?;
                        let cert_der = validation::load_certificate(cert_path)?;
                        let validity = x509::validity(&cert_der)
                            .context("decode signer certificate validity")?;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .context("system clock is before Unix epoch")?
                            .as_secs() as i64;
                        if !validity.is_valid_at(now) && !allow_expired_certificate {
                            anyhow::bail!("signer certificate is outside its validity interval; pass --allow-expired-certificate explicitly");
                        }
                        let key = pkix::SoftPrivateKey::from_path(key_path)?;
                        let signed = cades::sign_bes_pkix(&content, &cert_der, &key, !attached);
                        drop(key);
                        let signed = signed?;
                        print_signer_identity(&cert_der);
                        print_signer_validity(&validity, now);
                        let key_line = match x509::subject_public_key(&cert_der) {
                            Ok(x509::SubjectPublicKey::Rsa { modulus, .. }) => {
                                format!("key: RSA-{}", rsa_modulus_bits(&modulus))
                            }
                            Ok(x509::SubjectPublicKey::EcP256 { .. }) => "key: ECDSA P-256".into(),
                            Ok(x509::SubjectPublicKey::Gost { curve_oid, .. }) => {
                                format!("key: GOST {curve_oid}")
                            }
                            Err(e) => format!("key: <unknown: {e:#}>"),
                        };
                        (
                            signed,
                            format!("key source: pem {}", key_path.display()),
                            key_line,
                            cades::OID_SHA256,
                        )
                    } else {
                        let image_dirs =
                            resolve_image_dirs(&container_dir, containers_root.as_deref())?;
                        let mut token_pin = if image_dirs.is_empty() {
                            read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?
                        } else {
                            None
                        };
                        let (c, source) = open_classic_container(
                            &image_dirs,
                            index,
                            reader.as_deref(),
                            parse_optional_path(path)?,
                            max_depth,
                            token_pin.take(),
                        )?;

                        let cert = c.certificate.as_deref().context(
                            "header.key does not contain a parseable X.509 certificate; CAdES requires the signer certificate"
                        )?;
                        let validity =
                            x509::validity(cert).context("decode signer certificate validity")?;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .context("system clock is before Unix epoch")?
                            .as_secs() as i64;
                        let cert_current = validity.is_valid_at(now);
                        if !cert_current && !allow_expired_certificate {
                            anyhow::bail!("signer certificate is outside its validity interval; choose another container or pass --allow-expired-certificate explicitly");
                        }
                        let mut pin = read_container_pin(container_pin, container_pin_file)?;
                        let unlocked = c.unlock(&pin);
                        pin.zeroize();
                        let mut key = unlocked?;

                        let signed = cades::sign_bes(
                            &content,
                            cert,
                            &c.curve,
                            &key.private_le,
                            &key.public_x_le,
                            &key.public_y_le,
                            !attached,
                        );
                        key.private_le.zeroize();
                        let signed = signed?;
                        let digest_oid = if c.curve.bytes == 32 {
                            cades::OID_DIGEST_256
                        } else {
                            cades::OID_DIGEST_512
                        };
                        print_signer_identity(cert);
                        print_signer_validity(&validity, now);
                        (
                            signed,
                            format!("container: {source}"),
                            format!("curve: {}", c.curve.name),
                            digest_oid,
                        )
                    };

                    let (output_der, profile, timestamp_info) =
                        if let Some(tsa_url) = tsa.as_deref() {
                            let ts = timestamp::request_timestamp(
                                tsa_url,
                                &signed.signature,
                                digest_oid_for_tsa,
                                tsa_policy.as_deref(),
                                tsa_timeout_secs,
                            )?;
                            let der = cades::add_signature_timestamp(&signed.der, &ts.token)?;
                            (der, "CAdES-T", Some(ts.info))
                        } else {
                            (signed.der.clone(), "CAdES-BES", None)
                        };
                    fs::write(&out, &output_der)
                        .with_context(|| format!("write CAdES {}", out.display()))?;

                    println!(
                        "profile: {profile} ({})",
                        if attached { "attached" } else { "detached" }
                    );
                    println!("output: {}", out.display());
                    if let Some(ts) = &timestamp_info {
                        println!("timestamp: {}", ts.gen_time);
                    }

                    if verbose {
                        println!("{source}");
                        println!("{key_line}");
                        println!("certificate: {} bytes", signed.certificate.len());
                        println!("content digest: {}", hex::encode(&signed.content_digest));
                        println!("signature: {} bytes", signed.signature.len());
                        println!("content: {}", input.display());
                        if let Some(ts) = timestamp_info {
                            println!("RFC3161 timestamp: yes");
                            println!("  genTime: {}", ts.gen_time);
                            println!("  messageImprint algorithm: {}", ts.digest_oid);
                            println!("  messageImprint: {}", hex::encode(ts.message_imprint));
                            println!("  TSA token CMS signature: locally verified");
                            println!(
                                "  PKI trust/revocation policy: use an external trusted validator"
                            );
                        }
                        // Diagnostic only: the signature is already written, so a
                        // local verify error must not turn the command into FAIL.
                        let verified = if attached {
                            cades::verify(&output_der, None)
                        } else {
                            cades::verify(&output_der, Some(&content))
                        };
                        match verified {
                            Ok(verified) => println!(
                                "local verify: signature={} messageDigest={} signingCertV2={} sid={}",
                                verified.signature_valid,
                                verified.message_digest_valid,
                                verified.signing_certificate_v2_valid,
                                verified.signer_id_matches_certificate
                            ),
                            Err(e) => println!("local verify: error: {e:#}"),
                        }
                    }
                    Ok(())
                })();
                match outcome {
                    Ok(()) => print_ok_fail(true),
                    Err(e) => {
                        print_ok_fail(false);
                        if verbose {
                            eprintln!("{e:#}");
                        }
                        std::process::exit(1);
                    }
                }
            }
            CadesCommand::Enhance {
                signature,
                out,
                tsa,
                tsa_policy,
                tsa_timeout_secs,
                chain_cert,
                crl,
                ocsp_file,
                ocsp_url,
                no_fetch_validation,
                fetch_timeout_secs,
            } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let parsed = cades::parse(&raw).context("parse input CAdES")?;
                if parsed.signature_timestamp_token.is_none() {
                    anyhow::bail!("cades enhance requires CAdES-T input; create T first with `cades sign --tsa ...`");
                }
                let timing = xlong::signature_timestamp_within_signer_validity(&raw)
                    .context("cannot create conformant CAdES-XLT1 from this CAdES-T")?;
                println!("long-term timing precheck: OK ({timing})");

                let manual_chain = chain_cert
                    .iter()
                    .map(|p| validation::load_certificate(p))
                    .collect::<Result<Vec<_>>>()?;
                let manual_crls = crl
                    .iter()
                    .map(|p| validation::load_crl(p))
                    .collect::<Result<Vec<_>>>()?;

                let inner_ts = timestamp::token_matches_signature(
                    parsed
                        .signature_timestamp_token
                        .as_deref()
                        .expect("checked above"),
                    &parsed.signature,
                )
                .context("validate signature timestamp before collecting OCSP")?;
                let inner_ts_unix = x509::generalized_time_to_unix(&inner_ts.gen_time)?;

                println!("collecting validation material...");
                let material = validation::collect(
                    &parsed.certificate,
                    manual_chain,
                    manual_crls,
                    ocsp_file.as_deref(),
                    ocsp_url.as_deref(),
                    !no_fetch_validation,
                    fetch_timeout_secs,
                    inner_ts_unix,
                )?;
                println!("CA certificates: {}", material.ca_chain.len());
                println!("signer OCSP: thisUpdate={} producedAt={} nextUpdate={} embedded responder cert(s)={}",
                    material.signer_ocsp.this_update,
                    material.signer_ocsp.produced_at,
                    material.signer_ocsp.next_update.as_deref().unwrap_or("<absent>"),
                    material.signer_ocsp.embedded_certificates.len());
                println!("CA CRLs: {}", material.ca_crls.len());

                println!("building XLT1 with complete outer signer/TSA validation evidence...");
                let enhanced = xlong::enhance_x_long_type_1(
                    &raw,
                    &material,
                    &tsa,
                    tsa_policy.as_deref(),
                    tsa_timeout_secs,
                    fetch_timeout_secs,
                )?;
                let audit = xlong::audit_x_long_type_1(&enhanced.der);
                for c in &audit.checks {
                    println!(
                        "self-audit {}: {} — {}",
                        c.name,
                        if c.ok { "OK" } else { "FAIL" },
                        c.detail
                    );
                }
                if !audit.is_conformant() {
                    anyhow::bail!("generated signature failed local CAdES-XLT1 self-audit; output was not written");
                }
                fs::write(&out, &enhanced.der)
                    .with_context(|| format!("write CAdES-X Long Type 1 {}", out.display()))?;
                println!("CAdES-X Long Type 1: {}", out.display());
                println!(
                    "certificateRefs/certificateValues: {} CA certificates",
                    enhanced.ca_count
                );
                println!(
                    "revocationRefs/revocationValues: {} signer OCSP + {} CA CRL(s)",
                    enhanced.ocsp_count, enhanced.crl_count
                );
                println!(
                    "signature timestamp TSA evidence: {} CA cert(s), {} OCSP, {} CRL(s)",
                    enhanced.signature_tsa_evidence.ca_count,
                    enhanced.signature_tsa_evidence.ocsp_count,
                    enhanced.signature_tsa_evidence.crl_count
                );
                println!("CAdES-C timestamp: yes");
                println!("  genTime: {}", enhanced.esc_timestamp.gen_time);
                println!(
                    "  messageImprint algorithm: {}",
                    enhanced.esc_timestamp.digest_oid
                );
                println!(
                    "  messageImprint: {}",
                    hex::encode(enhanced.esc_timestamp.message_imprint)
                );
                println!(
                    "CAdES-C timestamp TSA evidence: {} CA cert(s), {} OCSP, {} CRL(s)",
                    enhanced.esc_tsa_evidence.ca_count,
                    enhanced.esc_tsa_evidence.ocsp_count,
                    enhanced.esc_tsa_evidence.crl_count
                );
                println!("private key/Rutoken: not used during T -> X Long Type 1 enhancement");
            }
            CadesCommand::Archive {
                signature,
                content,
                content_hash,
                out,
                tsa,
                tsa_policy,
                tsa_timeout_secs,
                fetch_timeout_secs,
            } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let content_bytes = match content.as_ref() {
                    Some(path) => Some(
                        fs::read(path)
                            .with_context(|| format!("read content {}", path.display()))?,
                    ),
                    None => None,
                };
                let hash_bytes = match content_hash.as_ref() {
                    Some(h) => Some(parse_content_hash_hex(h)?),
                    None => None,
                };
                let external = archive::ExternalData::from_parts(
                    content_bytes.as_deref(),
                    hash_bytes.as_deref(),
                )?;
                let before_count = archive::archive_timestamp_v3_count(&raw)?;
                if before_count == 0 {
                    println!("CAdES-A precheck: validating XLT1 base and signed content...");
                } else {
                    println!("CAdES-A renewal precheck: validating XLT1 base and {before_count} existing archive timestamp(s)...");
                }
                let archived = archive::add_archive_timestamp_v3(
                    &raw,
                    external,
                    &tsa,
                    tsa_policy.as_deref(),
                    tsa_timeout_secs,
                    fetch_timeout_secs,
                )?;
                let audit = archive::audit_cades_a(&archived.der, external);
                for c in &audit.checks {
                    println!(
                        "self-audit {}: {} — {}",
                        c.name,
                        if c.ok { "OK" } else { "FAIL" },
                        c.detail
                    );
                }
                if !audit.is_conformant() {
                    anyhow::bail!(
                        "generated CAdES-A failed local ATSv3 self-audit; output was not written"
                    );
                }
                fs::write(&out, &archived.der)
                    .with_context(|| format!("write CAdES-A {}", out.display()))?;
                let total_count = archived.previous_archive_count + 1;
                if archived.previous_archive_count == 0 {
                    println!("CAdES-A (archive-time-stamp-v3): {}", out.display());
                } else {
                    println!("CAdES-A renewed: {}", out.display());
                }
                println!(
                    "archive timestamp #{}: {}",
                    total_count, archived.timestamp.gen_time
                );
                println!(
                    "archive digest algorithm: {}",
                    archived.timestamp.digest_oid
                );
                println!(
                    "archive messageImprint: {}",
                    hex::encode(&archived.timestamp.message_imprint)
                );
                println!("ATSHashIndexV3: {} root certificate(s), {} root revocation item(s), {} unsigned AttributeValue(s)",
                    archived.hash_index.certificates, archived.hash_index.revocations, archived.hash_index.unsigned_attribute_values);
                println!(
                    "archive TSA evidence: {} CA cert(s), {} OCSP, {} CRL(s)",
                    archived.tsa_evidence.ca_count,
                    archived.tsa_evidence.ocsp_count,
                    archived.tsa_evidence.crl_count
                );
                println!("archive timestamp count: {total_count}");
                println!("private key/Rutoken: not used during CAdES-A archive timestamp addition/renewal");
            }
            CadesCommand::Attach {
                signature,
                content,
                out,
            } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let content_raw = fs::read(&content)
                    .with_context(|| format!("read content {}", content.display()))?;
                let before = cades::parse(&raw)?;
                let attached = archive::attach_original_content(&raw, &content_raw)?;
                let report = verification::analyze(&attached, None)?;
                print_local_verification(&report);
                if !report.is_valid() {
                    anyhow::bail!(
                        "attached CMS/CAdES failed local verification; output was not written"
                    );
                }
                fs::write(&out, &attached)
                    .with_context(|| format!("write attached CAdES {}", out.display()))?;
                println!("attached CMS/CAdES: {}", out.display());
                println!(
                    "source mode: {}",
                    if before.detached {
                        "detached"
                    } else {
                        "attached"
                    }
                );
                println!("output mode: attached");
                println!("embedded content: {} bytes", content_raw.len());
                println!("SignerInfo and unsigned attributes: byte-for-byte unchanged");
            }
            CadesCommand::Detach {
                signature,
                out,
                content_out,
            } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let before = cades::parse(&raw)?;
                let (detached, content_raw) = archive::detach_original_content(&raw)?;
                let report = verification::analyze(&detached, Some(&content_raw))?;
                print_local_verification(&report);
                if !report.is_valid() {
                    anyhow::bail!(
                        "detached CMS/CAdES failed local verification; output was not written"
                    );
                }
                fs::write(&out, &detached)
                    .with_context(|| format!("write detached CAdES {}", out.display()))?;
                if let Some(path) = content_out.as_ref() {
                    fs::write(path, &content_raw)
                        .with_context(|| format!("write extracted content {}", path.display()))?;
                    println!("extracted content: {}", path.display());
                }
                println!("detached CMS/CAdES: {}", out.display());
                println!(
                    "source mode: {}",
                    if before.detached {
                        "detached"
                    } else {
                        "attached"
                    }
                );
                println!("output mode: detached");
                println!("extracted content: {} bytes", content_raw.len());
                println!("SignerInfo and unsigned attributes: byte-for-byte unchanged");
            }
            CadesCommand::Audit {
                signature,
                content,
                content_hash,
            } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let content_bytes = match content.as_ref() {
                    Some(path) => Some(
                        fs::read(path)
                            .with_context(|| format!("read content {}", path.display()))?,
                    ),
                    None => None,
                };
                let hash_bytes = match content_hash.as_ref() {
                    Some(h) => Some(parse_content_hash_hex(h)?),
                    None => None,
                };
                let external = archive::ExternalData::from_parts(
                    content_bytes.as_deref(),
                    hash_bytes.as_deref(),
                )?;
                let audit = xlong::audit_x_long_type_1(&raw);
                println!("source: {}", signature.display());
                for c in &audit.checks {
                    println!(
                        "{}: {} — {}",
                        c.name,
                        if c.ok { "OK" } else { "FAIL" },
                        c.detail
                    );
                }
                println!(
                    "XLT1 local semantic audit: {}",
                    if audit.is_conformant() {
                        "PASS"
                    } else {
                        "FAIL"
                    }
                );
                if !audit.is_conformant() {
                    anyhow::bail!("CAdES-XLT1 audit failed");
                }
                let archive_count = archive::archive_timestamp_v3_count(&raw)?;
                if archive_count > 0 {
                    let aa = archive::audit_cades_a(&raw, external);
                    for c in &aa.checks {
                        println!(
                            "CAdES-A {}: {} — {}",
                            c.name,
                            if c.ok { "OK" } else { "FAIL" },
                            c.detail
                        );
                    }
                    println!(
                        "CAdES-A local ATSv3 audit: {}",
                        if aa.is_conformant() { "PASS" } else { "FAIL" }
                    );
                    if !aa.is_conformant() {
                        anyhow::bail!("CAdES-A audit failed");
                    }
                }
            }
            CadesCommand::Inspect { signature } => {
                let raw = fs::read(&signature)
                    .with_context(|| format!("read signature {}", signature.display()))?;
                let p = cades::parse(&raw)?;
                let spk = x509::subject_public_key(&p.certificate)?;
                println!("source: {}", signature.display());
                let xp = xlong::inspect_presence(&raw)?;
                let archive_count = archive::archive_timestamp_v3_count(&raw)?;
                let profile = if archive_count > 0 {
                    "CAdES-A"
                } else if xp.is_x_long_type_1() {
                    "CAdES-X Long Type 1"
                } else if p.signature_timestamp_token.is_some() {
                    "CAdES-T"
                } else {
                    "CAdES-BES"
                };
                println!("profile: {profile}");
                if archive_count > 0 {
                    println!("archiveTimeStampV3: {}", archive_count);
                    for (i, info) in archive::archive_timestamp_v3_infos(&raw)?
                        .iter()
                        .enumerate()
                    {
                        println!(
                            "  [{}] genTime={} digestAlgorithm={}",
                            i, info.gen_time, info.digest_oid
                        );
                    }
                }
                println!("SignedData version: {}", p.version);
                println!("mode: {}", if p.detached { "detached" } else { "attached" });
                println!("digestAlgorithm: {}", p.digest_oid);
                println!("signatureAlgorithm: {}", p.signature_oid);
                match &spk {
                    x509::SubjectPublicKey::Gost { curve_oid, .. } => {
                        println!("curve: {curve_oid}")
                    }
                    x509::SubjectPublicKey::Rsa { modulus, .. } => {
                        println!("key: RSA-{}", rsa_modulus_bits(modulus))
                    }
                    x509::SubjectPublicKey::EcP256 { .. } => {
                        println!("key: ECDSA P-256 (curve: 1.2.840.10045.3.1.7)")
                    }
                }
                println!("certificate: {} bytes", p.certificate.len());
                println!("content-type: {}", p.content_type_oid);
                println!("message-digest: {}", hex::encode(&p.message_digest));
                match &p.signing_certificate_v2 {
                    Some(sc) => {
                        println!("signingCertificateV2: yes");
                        println!("  hashAlgorithm: {}", sc.hash_algorithm_oid);
                        println!("  certHash: {}", hex::encode(&sc.cert_hash));
                    }
                    None => println!("signingCertificateV2: no"),
                }
                println!("signature bytes: {}", p.signature.len());
                match &p.signature_timestamp_token {
                    Some(token) => {
                        let ts = timestamp::token_matches_signature(token, &p.signature)?;
                        println!("signatureTimeStampToken: yes");
                        println!("  genTime: {}", ts.gen_time);
                        println!("  messageImprint: valid");
                        println!("  digestAlgorithm: {}", ts.digest_oid);
                    }
                    None => println!("signatureTimeStampToken: no"),
                }
                if xp.certificate_refs
                    || xp.revocation_refs
                    || xp.certificate_values
                    || xp.revocation_values
                    || xp.esc_timestamp
                {
                    println!(
                        "completeCertificateRefs: {}",
                        if xp.certificate_refs { "yes" } else { "no" }
                    );
                    println!(
                        "completeRevocationRefs: {}",
                        if xp.revocation_refs { "yes" } else { "no" }
                    );
                    println!(
                        "certificateValues: {}",
                        if xp.certificate_values { "yes" } else { "no" }
                    );
                    println!(
                        "revocationValues: {}",
                        if xp.revocation_values { "yes" } else { "no" }
                    );
                    println!(
                        "CAdES-C-time-stamp: {}",
                        if xp.esc_timestamp { "yes" } else { "no" }
                    );
                    if xp.esc_timestamp {
                        match xlong::verify_esc_timestamp_imprint(&raw) {
                            Ok(xts) => {
                                println!("  genTime: {}", xts.gen_time);
                                println!("  messageImprint: valid");
                                println!("  digestAlgorithm: {}", xts.digest_oid);
                            }
                            Err(e) => println!("  messageImprint: INVALID ({e:#})"),
                        }
                    }
                    if xp.is_x_long_type_1() {
                        let audit = xlong::audit_x_long_type_1(&raw);
                        println!("XLT1 semantic audit:");
                        for c in &audit.checks {
                            println!(
                                "  {}: {} — {}",
                                c.name,
                                if c.ok { "OK" } else { "FAIL" },
                                c.detail
                            );
                        }
                        println!(
                            "  result: {}",
                            if audit.is_conformant() {
                                "PASS"
                            } else {
                                "FAIL"
                            }
                        );
                    }
                }
            }
            CadesCommand::Verify {
                signature,
                content,
                content_hash,
                offline,
                refresh,
                fetch_timeout_secs,
                verbose,
            } => {
                let outcome = (|| -> Result<()> {
                    let raw = fs::read(&signature)
                        .with_context(|| format!("read signature {}", signature.display()))?;
                    let content_bytes = match content.as_ref() {
                        Some(path) => Some(
                            fs::read(path)
                                .with_context(|| format!("read content {}", path.display()))?,
                        ),
                        None => None,
                    };
                    let hash_bytes = match content_hash.as_ref() {
                        Some(h) => Some(parse_content_hash_hex(h)?),
                        None => None,
                    };
                    let external = archive::ExternalData::from_parts(
                        content_bytes.as_deref(),
                        hash_bytes.as_deref(),
                    )?;
                    let report = verification::analyze_ex(&raw, external)?;
                    if !report.is_valid() {
                        // Still surface signer identity when the CMS parsed far enough.
                        if let Ok(parsed) = cades::parse(&raw) {
                            print_signer_identity(&parsed.certificate);
                            if let Ok(v) = x509::validity(&parsed.certificate) {
                                print_signer_validity(&v, unix_now());
                            }
                            println!("profile: {}", report.profile.as_str());
                        }
                        if verbose {
                            print_local_verification(&report);
                        }
                        anyhow::bail!("local CAdES verification failed");
                    }

                    let parsed = cades::parse(&raw)?;
                    let embedded = xlong::extract_certificate_values(&raw).ok().flatten();
                    let mut cache = certcache::CertCache::load();
                    let now = unix_now();
                    let pki = validation::verify_signer_pki(
                        &parsed.certificate,
                        embedded.as_deref(),
                        &mut cache,
                        !offline,
                        refresh,
                        fetch_timeout_secs,
                        now,
                    )?;
                    if let Err(e) = cache.save() {
                        if verbose {
                            eprintln!("warning: could not persist certificate cache: {e:#}");
                        }
                    }

                    print_signer_identity(&parsed.certificate);
                    print_signer_validity(&pki.cert_check.validity, now);
                    print_signer_revocation(
                        pki.cert_check.revocation_status.as_ref(),
                        pki.cert_check.validity.is_valid_at(now),
                    );
                    println!(
                        "profile: {} ({})",
                        report.profile.as_str(),
                        if report.base.detached {
                            "detached"
                        } else {
                            "attached"
                        }
                    );
                    if let Some(t) = &report.base.timestamp_gen_time {
                        println!("timestamp: {t}");
                    }
                    if report.archive_count > 0 {
                        println!("archive timestamps: {}", report.archive_count);
                    }
                    if pki.chain_depth == 0 {
                        println!("chain: self-signed");
                    } else {
                        println!("chain: {} CA certificate(s)", pki.chain_depth);
                    }

                    if verbose {
                        print_local_verification(&report);
                        print_pki_verification(&pki, now);
                    }
                    if !pki.is_valid(now) {
                        anyhow::bail!("PKI validation failed");
                    }
                    Ok(())
                })();

                match outcome {
                    Ok(()) => print_ok_fail(true),
                    Err(e) => {
                        print_ok_fail(false);
                        if verbose {
                            eprintln!("{e:#}");
                        }
                        std::process::exit(1);
                    }
                }
            }
        },
        Command::Encrypt {
            input,
            out,
            recipient_cert,
            alg,
        } => {
            let plaintext = fs::read(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let content_alg = enveloped::ContentAlg::parse(&alg)?;
            let mut recipients = Vec::new();
            for path in &recipient_cert {
                let cert = container::read_certificate_file(path)?;
                recipients.push(enveloped::RecipientKey { cert_der: cert });
            }
            let cms = enveloped::encrypt_with(&plaintext, &recipients, content_alg)?;
            fs::write(&out, &cms).with_context(|| format!("write {}", out.display()))?;
            println!(
                "encrypted {} bytes [{}] → {}",
                plaintext.len(),
                content_alg.as_str(),
                out.display()
            );
        }
        Command::Decrypt {
            input,
            out,
            container_dir,
            containers_root,
            reader,
            path,
            index,
            max_depth,
            token_pin,
            token_pin_file,
            container_pin,
            container_pin_file,
        } => {
            let cms = fs::read(&input)
                .with_context(|| format!("read {}", input.display()))?;
            let image_dirs = resolve_image_dirs(&container_dir, containers_root.as_deref())?;
            let mut token_pin = if image_dirs.is_empty() {
                read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?
            } else {
                None
            };
            let (c, _source) = open_classic_container(
                &image_dirs,
                index,
                reader.as_deref(),
                parse_optional_path(path)?,
                max_depth,
                token_pin.take(),
            )?;
            let cert = c
                .certificate
                .as_ref()
                .context("container has no certificate for RecipientInfo match")?
                .clone();
            let mut pin = read_container_pin(container_pin, container_pin_file)?;
            let unlocked = c.unlock(&pin);
            pin.zeroize();
            let mut key = unlocked?;
            let plaintext = enveloped::decrypt(
                &cms,
                &enveloped::DecryptKey {
                    private_le: std::mem::take(&mut key.private_le),
                    curve: c.curve.clone(),
                    cert_der: cert,
                },
            )?;
            key.private_le.zeroize();
            fs::write(&out, &plaintext)
                .with_context(|| format!("write {}", out.display()))?;
            println!("decrypted {} bytes → {}", plaintext.len(), out.display());
        }
        Command::Daemon { config, listen } => {
            daemon::run(daemon::DaemonOptions {
                config_path: config,
                listen_override: listen,
            })?;
        }
        Command::NmcadesHost {
            config,
            tsa,
            http,
            _chrome_args: _,
        } => {
            nmcades_host::run(nmcades_host::NmcadesHostOptions {
                config_path: config,
                tsa,
                http_listen: http,
            })?;
        }
        Command::Xml { cmd } => match cmd {
            XmlCommand::Sign {
                input,
                out,
                r#type,
                profile,
                container_dir,
                containers_root,
                reader,
                path,
                index,
                max_depth,
                token_pin,
                token_pin_file,
                container_pin,
                container_pin_file,
                tsa,
                tsa_policy,
                tsa_timeout_secs,
                xpath,
                allow_expired_certificate,
                verbose,
            } => {
                let outcome = (|| -> Result<()> {
                    let content = fs::read_to_string(&input)
                        .with_context(|| format!("read XML {}", input.display()))?;
                    let signature_type = parse_xml_signature_type(&r#type)?;
                    let xades_flags = parse_xades_profile(&profile)?;
                    if matches!(
                        xades_flags,
                        xmldsig::XADES_T | xmldsig::XADES_XLT1 | xmldsig::XADES_A
                    ) && tsa.as_deref().unwrap_or("").is_empty()
                    {
                        anyhow::bail!("profile {profile} requires --tsa URL");
                    }

                    let image_dirs =
                        resolve_image_dirs(&container_dir, containers_root.as_deref())?;
                    let mut token_pin = if image_dirs.is_empty() {
                        read_optional_secret(token_pin, token_pin_file, "Rutoken PIN")?
                    } else {
                        None
                    };
                    let (c, source) = open_classic_container(
                        &image_dirs,
                        index,
                        reader.as_deref(),
                        parse_optional_path(path)?,
                        max_depth,
                        token_pin.take(),
                    )?;
                    let cert = c.certificate.as_deref().context(
                        "header.key does not contain a parseable X.509 certificate; XML signing requires the signer certificate",
                    )?;
                    let validity =
                        x509::validity(cert).context("decode signer certificate validity")?;
                    let now = unix_now();
                    if !validity.is_valid_at(now) && !allow_expired_certificate {
                        anyhow::bail!("signer certificate is outside its validity interval; pass --allow-expired-certificate to continue");
                    }

                    let mut pin = read_container_pin(container_pin, container_pin_file)?;
                    let unlocked = c.unlock(&pin);
                    pin.zeroize();
                    let mut key = unlocked?;

                    let digest_method = xmldsig::digest_method_uri(c.curve.bytes)?;
                    let signature_method = xmldsig::signature_method_uri(c.curve.bytes)?;
                    let signed = xmldsig::sign_xml(&xmldsig::SignXmlParams {
                        content: &content,
                        cert_der: cert,
                        curve: &c.curve,
                        private_le: &key.private_le,
                        public_x_le: &key.public_x_le,
                        public_y_le: &key.public_y_le,
                        signature_type,
                        digest_method,
                        signature_method,
                        xpath: xpath.as_deref(),
                        xades_flags,
                        tsa_url: tsa.as_deref(),
                        tsa_policy: tsa_policy.as_deref(),
                        tsa_timeout_secs,
                    });
                    key.private_le.zeroize();
                    let signed = signed?;
                    fs::write(&out, &signed)
                        .with_context(|| format!("write signed XML {}", out.display()))?;

                    print_signer_identity(cert);
                    print_signer_validity(&validity, now);
                    println!(
                        "profile: {} ({})",
                        xml_profile_label(xades_flags),
                        xml_type_label(signature_type)
                    );
                    println!("output: {}", out.display());
                    if verbose {
                        println!("container: {source}");
                        println!("curve: {}", c.curve.name);
                        println!("bytes: {}", signed.len());
                    }
                    Ok(())
                })();
                match outcome {
                    Ok(()) => print_ok_fail(true),
                    Err(e) => {
                        print_ok_fail(false);
                        if verbose {
                            eprintln!("{e:#}");
                        }
                        std::process::exit(1);
                    }
                }
            }
            XmlCommand::Verify {
                input,
                xpath,
                verbose,
            } => {
                let outcome = (|| -> Result<()> {
                    let signed = fs::read_to_string(&input)
                        .with_context(|| format!("read signed XML {}", input.display()))?;
                    let v = xmldsig::verify_xml(&signed, xpath.as_deref())?;
                    if let Some(cert) = v.certificate_der.as_deref() {
                        print_signer_identity(cert);
                        if let Ok(validity) = x509::validity(cert) {
                            print_signer_validity(&validity, unix_now());
                        }
                    }
                    println!("profile: {}", detect_xml_profile_label(&signed));
                    println!("references: {}", if v.references_valid { "ok" } else { "FAIL" });
                    println!("signature: {}", if v.signature_valid { "ok" } else { "FAIL" });
                    if verbose {
                        println!("input: {}", input.display());
                        println!("bytes: {}", signed.len());
                    }
                    if !v.ok {
                        anyhow::bail!("XML signature verification failed");
                    }
                    Ok(())
                })();
                match outcome {
                    Ok(()) => print_ok_fail(true),
                    Err(e) => {
                        print_ok_fail(false);
                        if verbose {
                            eprintln!("{e:#}");
                        }
                        std::process::exit(1);
                    }
                }
            }
            XmlCommand::Archive {
                input,
                out,
                tsa,
                tsa_policy,
                tsa_timeout_secs,
                signature_id,
            } => {
                let mut signed = fs::read_to_string(&input)
                    .with_context(|| format!("read signed XML {}", input.display()))?;
                // Prefer digest width from embedded signer certificate when present.
                let digest_oid = match xmldsig::verify_xml(&signed, None)
                    .ok()
                    .and_then(|v| v.certificate_der)
                    .and_then(|c| x509::identity(&c).ok())
                    .and_then(|id| curves::by_oid(&id.curve_oid))
                {
                    Some(curve) if curve.bytes >= 64 => cades::OID_DIGEST_512,
                    _ => cades::OID_DIGEST_256,
                };
                xmldsig::add_archive_timestamp_xml(
                    &mut signed,
                    signature_id.as_deref(),
                    &tsa,
                    tsa_policy.as_deref(),
                    tsa_timeout_secs,
                    digest_oid,
                )?;
                fs::write(&out, &signed)
                    .with_context(|| format!("write archived XML {}", out.display()))?;
                println!("profile: {}", detect_xml_profile_label(&signed));
                println!("XAdES-A ArchiveTimeStamp added: {}", out.display());
                println!("private key/Rutoken: not used during XAdES-A archive timestamp");
            }
            XmlCommand::Inspect { input } => {
                let signed = fs::read_to_string(&input)
                    .with_context(|| format!("read signed XML {}", input.display()))?;
                println!("file: {}", input.display());
                println!("bytes: {}", signed.len());
                println!("profile: {}", detect_xml_profile_label(&signed));
                if signed.contains("SignatureValue") {
                    println!("SignatureValue: present");
                }
                if let Ok(v) = xmldsig::verify_xml(&signed, None) {
                    if let Some(cert) = v.certificate_der.as_deref() {
                        print_signer_identity(cert);
                    }
                    println!(
                        "local verify: references={} signature={}",
                        if v.references_valid { "ok" } else { "FAIL" },
                        if v.signature_valid { "ok" } else { "FAIL" }
                    );
                }
                for needle in [
                    "SignedProperties",
                    "SignatureTimeStamp",
                    "CompleteCertificateRefsV2",
                    "CompleteRevocationRefs",
                    "SigAndRefsTimeStampV2",
                    "CertificateValues",
                    "RevocationValues",
                ] {
                    if signed.contains(needle) {
                        println!("attribute: {needle}");
                    }
                }
            }
        },
    }
    Ok(())
}

fn parse_xml_signature_type(s: &str) -> Result<xmldsig::XmlSignatureType> {
    match s.to_ascii_lowercase().as_str() {
        "enveloped" | "0" => Ok(xmldsig::XmlSignatureType::Enveloped),
        "enveloping" | "1" => Ok(xmldsig::XmlSignatureType::Enveloping),
        "template" | "2" => Ok(xmldsig::XmlSignatureType::Template),
        other => anyhow::bail!("unknown --type {other:?} (expected enveloped|enveloping|template)"),
    }
}

fn parse_xades_profile(s: &str) -> Result<u32> {
    match s.to_ascii_lowercase().as_str() {
        "xmldsig" | "none" | "0" => Ok(xmldsig::XADES_NONE),
        "bes" | "xades-bes" => Ok(xmldsig::XADES_BES),
        "t" | "xades-t" => Ok(xmldsig::XADES_T),
        "xlt1" | "xades-xlt1" | "xlong" | "x-long" => Ok(xmldsig::XADES_XLT1),
        "a" | "archive" | "xades-a" => Ok(xmldsig::XADES_A),
        other => anyhow::bail!("unknown --profile {other:?} (expected xmldsig|bes|t|xlt1|a)"),
    }
}

fn xml_profile_label(flags: u32) -> &'static str {
    match flags {
        xmldsig::XADES_A => "XAdES-A",
        xmldsig::XADES_XLT1 => "XAdES-XLT1",
        xmldsig::XADES_T => "XAdES-T",
        xmldsig::XADES_BES => "XAdES-BES",
        _ => "XML-DSig",
    }
}

fn xml_type_label(t: xmldsig::XmlSignatureType) -> &'static str {
    match t {
        xmldsig::XmlSignatureType::Enveloped => "enveloped",
        xmldsig::XmlSignatureType::Enveloping => "enveloping",
        xmldsig::XmlSignatureType::Template => "template",
    }
}

fn detect_xml_profile_label(signed: &str) -> &'static str {
    if signed.contains("ArchiveTimeStamp") {
        "XAdES-A"
    } else if signed.contains("SigAndRefsTimeStampV2")
        || signed.contains("CompleteCertificateRefsV2")
    {
        "XAdES-XLT1"
    } else if signed.contains("SignatureTimeStamp") {
        "XAdES-T"
    } else if signed.contains("SignedProperties") {
        "XAdES-BES"
    } else if signed.contains("SignatureValue") {
        "XML-DSig"
    } else {
        "unknown"
    }
}