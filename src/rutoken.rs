// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Roman Yerin

use crate::container::ContainerFiles;
use anyhow::{anyhow, bail, Context, Result};
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};
use std::collections::BTreeSet;
use std::ffi::CString;

const SW_OK: u16 = 0x9000;
const SW_FILE_NOT_FOUND: u16 = 0x6A82;
const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
const SW_EOF_WARNING: u16 = 0x6282;

const MF: u16 = 0x3F00;
// Logical file numbers inside a CryptoPro container. The logical number is
// encoded in the LOW byte of the physical EF FID: xx01..xx06.  The high
// byte is carrier/container-specific and MUST NOT be inferred by the codec.
const CLASSIC_REQUIRED_EFS: [u16; 3] = [0x0001, 0x0002, 0x0003];
const CLASSIC_ALL_EFS: [u16; 6] = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileKind {
    Directory,
    Elementary,
    Unknown(u8),
}

impl FileKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Directory => "DF",
            Self::Elementary => "EF",
            Self::Unknown(_) => "??",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadAccess {
    None,
    Chv(u8),
    Never,
    Unknown(u8),
    NotSpecified,
}

impl ReadAccess {
    pub fn label(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::Chv(reference) => format!("CHV{reference}"),
            Self::Never => "never".into(),
            Self::Unknown(value) => format!("unknown(0x{value:02X})"),
            Self::NotSpecified => "not-specified".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FsEntry {
    pub fid: u16,
    pub kind: FileKind,
    pub size: Option<usize>,
    pub descriptor: Option<u8>,
    pub read_access: ReadAccess,
    pub sec_attr: Vec<u8>,
    pub fcp: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub path: Vec<u16>,
    pub kind: FileKind,
    pub size: Option<usize>,
    pub read_access: ReadAccess,
    pub sec_attr: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ContainerLocation {
    pub path: Vec<u16>,
    pub ef_ids: BTreeSet<u16>,
}

impl ContainerLocation {
    pub fn display_path(&self) -> String {
        format_path(&self.path)
    }
}

#[derive(Debug)]
struct ApduResponse {
    data: Vec<u8>,
    sw: u16,
}

#[derive(Clone, Debug)]
struct FcpInfo {
    fid: Option<u16>,
    size: Option<usize>,
    descriptor: Option<u8>,
    sec_attr: Vec<u8>,
    raw: Vec<u8>,
}

impl FcpInfo {
    fn kind(&self) -> FileKind {
        match self.descriptor {
            Some(0x38) => FileKind::Directory,
            Some(0x01) => FileKind::Elementary,
            Some(v) => FileKind::Unknown(v),
            None => FileKind::Unknown(0xff),
        }
    }
}

pub struct RutokenCard {
    // Fields drop in declaration order: disconnect the card before releasing
    // the PC/SC context.
    card: Card,
    _ctx: PcscContext,
    pub reader_name: String,
    pub atr: Vec<u8>,
}

pub fn list_readers() -> Result<Vec<String>> {
    let ctx = PcscContext::establish(Scope::User).context("SCardEstablishContext")?;
    let readers = ctx.list_readers_owned().context("SCardListReaders")?;
    Ok(readers
        .iter()
        .map(|r| r.to_string_lossy().into_owned())
        .collect())
}

impl RutokenCard {
    pub fn connect(reader_selector: Option<&str>) -> Result<Self> {
        let ctx = PcscContext::establish(Scope::User).context("SCardEstablishContext")?;
        let readers = ctx.list_readers_owned().context("SCardListReaders")?;
        if readers.is_empty() {
            bail!("no PC/SC readers found");
        }

        let reader = choose_reader(&readers, reader_selector)?;
        let reader_name = reader.to_string_lossy().into_owned();
        let card = ctx
            .connect(reader.as_c_str(), ShareMode::Shared, Protocols::ANY)
            .with_context(|| format!("connect to PC/SC reader {reader_name:?}"))?;
        let atr = card
            .status2_owned()
            .map(|s| s.atr().to_vec())
            .unwrap_or_default();

        Ok(Self {
            card,
            _ctx: ctx,
            reader_name,
            atr,
        })
    }

    /// Read-only diagnostic tree. No VERIFY/UPDATE/CREATE/DELETE APDUs are sent.
    pub fn tree(&self, max_depth: usize) -> Result<Vec<TreeEntry>> {
        self.select_mf()?;
        let mut out = Vec::new();
        self.walk_tree(&[], 0, max_depth, &mut out)?;
        Ok(out)
    }

    /// Find directories that contain the required classic CryptoPro logical EF set.
    /// The logical file number is the low byte of each EF FID:
    ///   xx01 masks.key, xx02 primary.key, xx03 header.key, xx04 masks2.key,
    ///   xx05 primary2.key, xx06 name.key.
    pub fn discover_classic_containers(&self, max_depth: usize) -> Result<Vec<ContainerLocation>> {
        self.select_mf()?;
        let roots = match self.list_current_df() {
            Ok(entries) => entries
                .into_iter()
                .filter(|e| e.kind == FileKind::Directory)
                .map(|e| e.fid)
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };

        let roots = if roots.is_empty() {
            // Fallback matching the top-level CryptoPro Rutoken carrier folders
            // commonly seen in the wild. We still validate each candidate by
            // SELECT and never write to it.
            self.probe_known_cryptopro_roots()?
        } else {
            roots
        };

        let mut found = Vec::new();
        for fid in roots {
            let path = vec![fid];
            self.scan_for_containers(&path, 1, max_depth, &mut found)?;
        }

        found.sort_by(|a, b| a.path.cmp(&b.path));
        found.dedup_by(|a, b| a.path == b.path);
        Ok(found)
    }

    pub fn read_classic_container(
        &self,
        path: &[u16],
        token_pin: Option<&[u8]>,
    ) -> Result<ContainerFiles> {
        if path.is_empty() {
            bail!("container path is empty");
        }

        // Determine the CHV from the card ACL, never by guessing. Rutoken Lite
        // may invalidate authentication very aggressively, so the actual read
        // path is able to re-VERIFY the SAME CHV/PIN when the card asks again.
        let auth = match self.required_read_chv(path)? {
            Some(reference) => {
                let pin = token_pin.ok_or_else(|| anyhow!(
                    "container {} requires CHV{} to read its EFs; pass --token-pin-file FILE (preferred) or --token-pin explicitly",
                    format_path(path), reference
                ))?;
                Some((reference, pin))
            }
            None => None,
        };

        let masks = self.read_logical_ef_required(path, 0x0001, "masks.key", auth)?;
        let primary = self.read_logical_ef_required(path, 0x0002, "primary.key", auth)?;
        let header = self.read_logical_ef_required(path, 0x0003, "header.key", auth)?;
        let masks2 = self.read_logical_ef_optional(path, 0x0004, auth)?;
        let primary2 = self.read_logical_ef_optional(path, 0x0005, auth)?;
        let name = self.read_logical_ef_optional(path, 0x0006, auth)?;

        Ok(ContainerFiles {
            header,
            masks,
            masks2,
            name,
            primary,
            primary2,
        })
    }

    pub fn select_container(
        &self,
        path: Option<&[u16]>,
        index: Option<usize>,
        max_depth: usize,
        token_pin: Option<&[u8]>,
    ) -> Result<(ContainerLocation, ContainerFiles)> {
        if let Some(path) = path {
            let entries = self.list_dir(path)?;
            let ids = entries
                .iter()
                .filter(|e| e.kind != FileKind::Directory)
                .map(|e| e.fid)
                .collect::<BTreeSet<_>>();
            let logical = logical_ef_set(path, &ids);
            if !CLASSIC_REQUIRED_EFS.iter().all(|fid| logical.contains(fid)) {
                bail!(
                    "{} does not contain required classic logical EFs 01, 02 and 03; found physical EFs: {}",
                    format_path(path),
                    format_fid_set(&ids)
                );
            }
            let location = ContainerLocation {
                path: path.to_vec(),
                ef_ids: ids,
            };
            let files = self.read_classic_container(path, token_pin)?;
            return Ok((location, files));
        }

        let locations = self.discover_classic_containers(max_depth)?;
        let location = match (locations.as_slice(), index) {
            ([], _) => bail!(
                "no classic CryptoPro container was found in the Rutoken filesystem; run `rutoken tree` to inspect it"
            ),
            (_, Some(i)) => locations.get(i).cloned().ok_or_else(|| {
                anyhow!("container index {i} is out of range; found {} container(s)", locations.len())
            })?,
            ([one], None) => one.clone(),
            (many, None) => {
                let mut msg = format!("{} classic containers found; specify --index or --path:\n", many.len());
                for (i, c) in many.iter().enumerate() {
                    msg.push_str(&format!("  [{i}] {}  EFs={}\n", c.display_path(), format_fid_set(&c.ef_ids)));
                }
                bail!("{msg}");
            }
        };
        let files = self.read_classic_container(&location.path, token_pin)?;
        Ok((location, files))
    }

    fn walk_tree(
        &self,
        parent: &[u16],
        depth: usize,
        max_depth: usize,
        out: &mut Vec<TreeEntry>,
    ) -> Result<()> {
        if depth > max_depth {
            return Ok(());
        }
        let entries = self.list_dir(parent)?;
        for entry in entries {
            let mut path = parent.to_vec();
            path.push(entry.fid);
            out.push(TreeEntry {
                path: path.clone(),
                kind: entry.kind,
                size: entry.size,
                read_access: entry.read_access.clone(),
                sec_attr: entry.sec_attr.clone(),
            });
            if entry.kind == FileKind::Directory && depth < max_depth {
                // Some unrelated/protected directories may reject SELECT/LIST.
                // Keep the diagnostic walk useful instead of aborting the whole card.
                let _ = self.walk_tree(&path, depth + 1, max_depth, out);
            }
        }
        Ok(())
    }

    fn scan_for_containers(
        &self,
        path: &[u16],
        depth: usize,
        max_depth: usize,
        found: &mut Vec<ContainerLocation>,
    ) -> Result<()> {
        if depth > max_depth {
            return Ok(());
        }

        let entries = match self.list_dir(path) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let ef_ids = entries
            .iter()
            .filter(|e| e.kind != FileKind::Directory)
            .map(|e| e.fid)
            .collect::<BTreeSet<_>>();
        let logical = logical_ef_set(path, &ef_ids);

        if CLASSIC_REQUIRED_EFS.iter().all(|fid| logical.contains(fid)) {
            found.push(ContainerLocation {
                path: path.to_vec(),
                ef_ids: ef_ids.clone(),
            });
        }

        if depth < max_depth {
            for entry in entries
                .into_iter()
                .filter(|e| e.kind == FileKind::Directory)
            {
                let mut child = path.to_vec();
                child.push(entry.fid);
                self.scan_for_containers(&child, depth + 1, max_depth, found)?;
            }
        }
        Ok(())
    }

    fn probe_known_cryptopro_roots(&self) -> Result<Vec<u16>> {
        let mut roots = Vec::new();
        for hi in 0x0a_u16..=0x18_u16 {
            let fid = hi << 8;
            self.select_mf()?;
            if let Ok(Some(fcp)) = self.select_fid_optional(fid) {
                if fcp.kind() == FileKind::Directory {
                    roots.push(fid);
                }
            }
        }
        Ok(roots)
    }

    fn list_dir(&self, path: &[u16]) -> Result<Vec<FsEntry>> {
        self.select_path(path)?;
        self.list_current_df().with_context(|| {
            format!(
                "list directory {}",
                if path.is_empty() {
                    "3F00".into()
                } else {
                    format_path(path)
                }
            )
        })
    }

    /// Implements Rutoken's SELECT-first / SELECT-next enumeration used by
    /// OpenSC's Rutoken driver:
    ///   first:  00 A4 00 00 00
    ///   next:   00 A4 00 02 02 <fid-be> 00
    /// Selecting a child DF changes the current DF, so we SELECT PARENT before
    /// requesting the following sibling.
    fn list_current_df(&self) -> Result<Vec<FsEntry>> {
        let mut out = Vec::new();
        let mut previous_raw: Option<[u8; 2]> = None;
        let mut previous_was_df = false;

        loop {
            if previous_was_df {
                self.select_parent()?;
            }

            let apdu = match previous_raw {
                None => vec![0x00, 0xA4, 0x00, 0x00, 0x00],
                Some(fid_be) => vec![0x00, 0xA4, 0x00, 0x02, 0x02, fid_be[0], fid_be[1], 0x00],
            };
            let response = self.transmit(&apdu)?;
            if response.sw == SW_FILE_NOT_FOUND {
                break;
            }
            check_sw("SELECT FILE (list)", response.sw)?;
            let fcp =
                parse_fcp(&response.data).context("parse FCP while listing Rutoken filesystem")?;
            let fid = fcp.fid.context("FCP has no tag 0x83 file identifier")?;
            let kind = fcp.kind();
            previous_raw = Some(fid.to_be_bytes());
            previous_was_df = kind == FileKind::Directory;
            out.push(FsEntry {
                fid,
                kind,
                size: fcp.size,
                descriptor: fcp.descriptor,
                read_access: read_access_from_sec_attr(&fcp.sec_attr),
                sec_attr: fcp.sec_attr.clone(),
                fcp: fcp.raw,
            });
        }

        Ok(out)
    }

    fn select_mf(&self) -> Result<FcpInfo> {
        self.select_fid(MF).context("select MF 3F00")
    }

    fn select_path(&self, path: &[u16]) -> Result<()> {
        self.select_mf()?;
        for fid in path {
            let fcp = self
                .select_fid(*fid)
                .with_context(|| format!("select {:04X} in {}", fid, format_path(path)))?;
            if fcp.kind() != FileKind::Directory {
                bail!("{:04X} in path {} is not a DF", fid, format_path(path));
            }
        }
        Ok(())
    }

    /// Rutoken Lite/ECP uses the standard ISO 7816 byte order for FIDs.
    /// This differs from the legacy Rutoken S OpenSC driver, which swaps bytes.
    fn select_fid(&self, fid: u16) -> Result<FcpInfo> {
        match self.select_fid_optional(fid)? {
            Some(info) => Ok(info),
            None => bail!("file {:04X} not found", fid),
        }
    }

    fn select_fid_optional(&self, fid: u16) -> Result<Option<FcpInfo>> {
        let [hi, lo] = fid.to_be_bytes();
        let response = self.transmit(&[0x00, 0xA4, 0x00, 0x00, 0x02, hi, lo, 0x00])?;
        if response.sw == SW_FILE_NOT_FOUND {
            return Ok(None);
        }
        check_sw(&format!("SELECT FILE {:04X}", fid), response.sw)?;
        Ok(Some(
            parse_fcp(&response.data).with_context(|| format!("parse FCP for {:04X}", fid))?,
        ))
    }

    fn select_parent(&self) -> Result<()> {
        let response = self.transmit(&[0x00, 0xA4, 0x03, 0x00, 0x00])?;
        check_sw("SELECT PARENT", response.sw)
    }

    /// Determine the CHV reference required to read the classic EFs from this
    /// container, using only each EF's security attributes (FCP tag 0x86).
    /// No PIN command is sent here.
    pub fn required_read_chv(&self, path: &[u16]) -> Result<Option<u8>> {
        let entries = self.list_dir(path)?;
        let mut refs = BTreeSet::new();

        for entry in entries
            .into_iter()
            .filter(|e| e.kind != FileKind::Directory)
        {
            let Some(logical) = logical_ef_id(path, entry.fid) else {
                continue;
            };
            if !CLASSIC_ALL_EFS.contains(&logical) {
                continue;
            }
            match entry.read_access {
                ReadAccess::None | ReadAccess::NotSpecified => {}
                ReadAccess::Chv(reference) => {
                    refs.insert(reference);
                }
                ReadAccess::Never => bail!(
                    "EF {:04X} ({}) in {} is marked read=never by ACL 0x86",
                    entry.fid, classic_ef_name(logical).unwrap_or("?"), format_path(path)
                ),
                ReadAccess::Unknown(value) => bail!(
                    "EF {:04X} ({}) in {} has unknown read ACL value 0x{value:02X}; refusing to guess a CHV reference",
                    entry.fid, classic_ef_name(logical).unwrap_or("?"), format_path(path)
                ),
            }
        }

        match refs.len() {
            0 => Ok(None),
            1 => Ok(refs.iter().next().copied()),
            _ => bail!(
                "container {} requires multiple CHV references for reading: {}; refusing to try more than one PIN reference",
                format_path(path),
                refs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(",")
            ),
        }
    }

    /// Read only header.key (logical EF 03) from a classic container.
    /// This is used for quick UUID extraction without reading the full container.
    /// Returns error if the container requires PIN authentication.
    pub fn dump_container_header(&self, path: &[u16]) -> Result<Vec<u8>> {
        if self.required_read_chv(path)?.is_some() {
            bail!(
                "container {} requires PIN to read; skipping UUID extraction",
                format_path(path)
            )
        }
        self.read_logical_ef_required(path, 0x0003, "header.key", None)
    }

    /// Try to read container header (EF 0003) without PIN.
    /// If the card requires authentication, silently returns None (instead of error).
    pub fn try_read_container_header_best_effort(&self, path: &[u16]) -> Result<Option<Vec<u8>>> {
        match self.read_logical_ef_required(path, 0x0003, "header.key", None) {
            Ok(data) => Ok(Some(data)),
            Err(e) => {
                // If the error is about security/authentication, return None instead of failing.
                // This allows `rutoken containers` to show PIN requirements without crashing.
                let msg = e.to_string();
                if msg.contains("6982")
                    || msg.contains("6983")
                    || msg.contains("6985")
                    || msg.contains("security status")
                {
                    Ok(None)
                } else {
                    // Other errors (e.g., file not found) still propagate
                    Err(e)
                }
            }
        }
    }

    /// Try to read name.key (EF 0006) without PIN, e.g. for UUID/friendly-name
    /// display. Returns `Ok(None)` if the EF is absent or requires
    /// authentication, instead of failing.
    pub fn try_read_container_name_best_effort(&self, path: &[u16]) -> Result<Option<Vec<u8>>> {
        match self.read_logical_ef_optional(path, 0x0006, None) {
            Ok(data) => Ok(data),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("6982")
                    || msg.contains("6983")
                    || msg.contains("6985")
                    || msg.contains("security status")
                {
                    Ok(None)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// OpenSC-compatible VERIFY for Rutoken ECP/Lite.
    ///
    /// Important safety property: this never tries another CHV and never tries
    /// another PIN. On SW=6F86 Rutoken asks for a logout/retry dance; OpenSC's
    /// card-rtecp.c does exactly one LOGOUT followed by the same VERIFY again.
    /// Any actual PIN failure (63Cx/6300/6983) aborts immediately.
    fn verify_with_rutoken_retry(&self, reference: u8, pin: &[u8]) -> Result<()> {
        if reference != 1 && reference != 2 {
            bail!("refusing VERIFY for unsupported CHV reference {reference}; Rutoken ECP/Lite ACL uses references 1 or 2");
        }
        if pin.is_empty() || pin.len() > 255 {
            bail!("token PIN length must be 1..255 bytes");
        }

        let first = self.verify_apdu(reference, pin)?;
        if first == 0x6F86 {
            // This is not a wrong-PIN retry. It is the Rutoken ECP/Lite quirk
            // handled by OpenSC: logout once, then repeat exactly the same
            // VERIFY once.
            self.logout()?;
            let second = self.verify_apdu(reference, pin)?;
            return self.check_verify_sw(reference, second, true);
        }
        self.check_verify_sw(reference, first, false)
    }

    fn verify_apdu(&self, reference: u8, pin: &[u8]) -> Result<u16> {
        let mut apdu = zeroize::Zeroizing::new(Vec::with_capacity(5 + pin.len()));
        apdu.extend_from_slice(&[0x00, 0x20, 0x00, reference, pin.len() as u8]);
        apdu.extend_from_slice(pin);
        Ok(self.transmit(&apdu)?.sw)
    }

    fn logout(&self) -> Result<()> {
        let response = self.transmit(&[0x80, 0x40, 0x00, 0x00])?;
        check_sw("Rutoken LOGOUT", response.sw)
    }

    fn check_verify_sw(&self, reference: u8, sw: u16, after_6f86_retry: bool) -> Result<()> {
        match sw {
            SW_OK => Ok(()),
            0x6983 => bail!("Rutoken CHV{reference} is blocked (SW=6983); aborting immediately"),
            sw if sw & 0xFFF0 == 0x63C0 => {
                let left = sw & 0x000F;
                bail!("Rutoken rejected CHV{reference} PIN; card reports {left} attempt(s) remaining (SW={sw:04X}). No further VERIFY was sent.")
            }
            0x6300 => bail!("Rutoken rejected CHV{reference} PIN (SW=6300). No further VERIFY and no retry-counter query were sent."),
            0x6F86 if after_6f86_retry => bail!("Rutoken returned SW=6F86 again after LOGOUT + same CHV{reference} VERIFY; refusing a second retry loop"),
            0x6F86 => bail!("internal error: unhandled Rutoken SW=6F86"),
            sw => bail!("Rutoken VERIFY CHV{reference} failed with SW={sw:04X}; no alternate CHV/PIN was attempted"),
        }
    }

    fn read_logical_ef_required(
        &self,
        path: &[u16],
        logical_fid: u16,
        name: &str,
        auth: Option<(u8, &[u8])>,
    ) -> Result<Vec<u8>> {
        let physical_fid = self
            .find_physical_ef_by_low_byte(path, logical_fid)?
            .ok_or_else(|| {
                anyhow!(
                    "required logical EF {:02X} ({name}) is absent in {}",
                    logical_fid & 0x00ff,
                    format_path(path)
                )
            })?;
        self.read_ef_optional(path, physical_fid, auth)?
            .ok_or_else(|| {
                anyhow!(
                    "EF {:04X} ({name}, logical {:02X}) disappeared from {}",
                    physical_fid,
                    logical_fid & 0x00ff,
                    format_path(path)
                )
            })
    }

    fn read_logical_ef_optional(
        &self,
        path: &[u16],
        logical_fid: u16,
        auth: Option<(u8, &[u8])>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(physical_fid) = self.find_physical_ef_by_low_byte(path, logical_fid)? else {
            return Ok(None);
        };
        self.read_ef_optional(path, physical_fid, auth)
    }

    /// Resolve a logical CryptoPro EF by the low byte of the physical FID.
    /// We deliberately enumerate the selected DF instead of synthesizing a
    /// physical FID from the parent directory name.
    fn find_physical_ef_by_low_byte(&self, path: &[u16], logical_fid: u16) -> Result<Option<u16>> {
        let suffix = logical_fid & 0x00ff;
        if !(1..=6).contains(&suffix) {
            bail!("unsupported classic logical EF {:04X}", logical_fid);
        }
        let matches = self
            .list_dir(path)?
            .into_iter()
            .filter(|e| e.kind != FileKind::Directory && (e.fid & 0x00ff) == suffix)
            .map(|e| e.fid)
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Ok(None),
            [fid] => Ok(Some(*fid)),
            _ => bail!(
                "{} contains multiple EFs with logical suffix {:02X}: {}",
                format_path(path),
                suffix,
                matches
                    .iter()
                    .map(|f| format!("{f:04X}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }

    fn select_ef_for_read(&self, path: &[u16], fid: u16) -> Result<Option<FcpInfo>> {
        self.select_path(path)?;
        let Some(fcp) = self.select_fid_optional(fid)? else {
            return Ok(None);
        };
        if fcp.kind() == FileKind::Directory {
            bail!("{:04X} in {} is a DF, expected EF", fid, format_path(path));
        }
        Ok(Some(fcp))
    }

    fn read_ef_optional(
        &self,
        path: &[u16],
        fid: u16,
        auth: Option<(u8, &[u8])>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(fcp) = self.select_ef_for_read(path, fid)? else {
            return Ok(None);
        };

        // Authenticate after selecting the EF. On some Rutoken Lite tokens the
        // security state is short-lived and may need to be renewed repeatedly.
        if let Some((reference, pin)) = auth {
            self.verify_with_rutoken_retry(reference, pin)?;
        }

        let value = self
            .read_current_ef(fcp.size, path, fid, auth)
            .with_context(|| format!("read EF {:04X} in {}", fid, format_path(path)))?;
        Ok(Some(value))
    }

    fn read_current_ef(
        &self,
        size: Option<usize>,
        path: &[u16],
        fid: u16,
        auth: Option<(u8, &[u8])>,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(size.unwrap_or(256));
        let mut offset = 0usize;

        loop {
            if let Some(size) = size {
                if offset >= size {
                    break;
                }
            }
            if offset > 0x7fff {
                bail!("EF is too large for short READ BINARY offset: {offset}");
            }

            let wanted = size.map(|s| (s - offset).min(0xff)).unwrap_or(0xff);
            if wanted == 0 {
                break;
            }
            let p1 = ((offset >> 8) & 0x7f) as u8;
            let p2 = (offset & 0xff) as u8;
            let apdu = [0x00, 0xB0, p1, p2, wanted as u8];
            let mut response = self.transmit(&apdu)?;

            // Rutoken Lite can drop CHV state between operations. If a READ
            // tells us authentication is required again, reselect exactly the
            // same EF, re-VERIFY the same CHV/PIN, then retry THIS READ once.
            if response.sw == SW_SECURITY_STATUS_NOT_SATISFIED || response.sw == 0x6F86 {
                let Some((reference, pin)) = auth else {
                    bail!("Rutoken returned SW={:04X} while reading EF {:04X} at offset {offset}, but no token PIN was provided", response.sw, fid);
                };
                self.select_ef_for_read(path, fid)?.ok_or_else(|| {
                    anyhow!(
                        "EF {:04X} disappeared from {} during re-authentication",
                        fid,
                        format_path(path)
                    )
                })?;
                self.verify_with_rutoken_retry(reference, pin)?;
                response = self.transmit(&apdu)?;
                if response.sw == SW_SECURITY_STATUS_NOT_SATISFIED || response.sw == 0x6F86 {
                    bail!("Rutoken still returned SW={:04X} after re-authenticating CHV{} for EF {:04X} offset {offset}; refusing another retry of the same operation", response.sw, reference, fid);
                }
            }

            match response.sw {
                SW_OK | SW_EOF_WARNING => {}
                0x6B00 => {
                    if size.is_none() {
                        break;
                    }
                    check_sw("READ BINARY", response.sw)?;
                }
                _ if response.sw & 0xff00 == 0x6c00 => {
                    let suggested = (response.sw & 0xff) as usize;
                    let suggested = if suggested == 0 { 256 } else { suggested };
                    let le = suggested.min(0xff) as u8;
                    let retry_apdu = [0x00, 0xB0, p1, p2, le];
                    let mut retry = self.transmit(&retry_apdu)?;
                    if retry.sw == SW_SECURITY_STATUS_NOT_SATISFIED || retry.sw == 0x6F86 {
                        let Some((reference, pin)) = auth else {
                            bail!("Rutoken requested re-authentication during READ BINARY 6Cxx retry, but no token PIN was provided");
                        };
                        self.select_ef_for_read(path, fid)?.ok_or_else(|| {
                            anyhow!(
                                "EF {:04X} disappeared from {} during re-authentication",
                                fid,
                                format_path(path)
                            )
                        })?;
                        self.verify_with_rutoken_retry(reference, pin)?;
                        retry = self.transmit(&retry_apdu)?;
                    }
                    check_sw("READ BINARY (retry after 6Cxx)", retry.sw)?;
                    if retry.data.is_empty() {
                        break;
                    }
                    offset += retry.data.len();
                    out.extend_from_slice(&retry.data);
                    continue;
                }
                _ => check_sw("READ BINARY", response.sw)?,
            }

            if response.data.is_empty() {
                break;
            }
            offset += response.data.len();
            out.extend_from_slice(&response.data);
            if response.sw == SW_EOF_WARNING {
                break;
            }
            if size.is_none() && response.data.len() < wanted {
                break;
            }
        }

        if let Some(size) = size {
            if out.len() < size {
                bail!("short EF read: got {} bytes, FCP says {}", out.len(), size);
            }
            out.truncate(size);
        }
        Ok(out)
    }

    fn transmit(&self, apdu: &[u8]) -> Result<ApduResponse> {
        let mut buffer = [0u8; 4096];
        let raw = self
            .card
            .transmit(apdu, &mut buffer)
            .with_context(|| format!("SCardTransmit APDU {}", hex::encode_upper(apdu)))?;
        if raw.len() < 2 {
            bail!(
                "short APDU response ({} bytes) for {}",
                raw.len(),
                hex::encode_upper(apdu)
            );
        }
        let sw = ((raw[raw.len() - 2] as u16) << 8) | raw[raw.len() - 1] as u16;
        Ok(ApduResponse {
            data: raw[..raw.len() - 2].to_vec(),
            sw,
        })
    }
}

fn choose_reader<'a>(readers: &'a [CString], selector: Option<&str>) -> Result<&'a CString> {
    if let Some(selector) = selector {
        let wanted = selector.to_ascii_lowercase();
        let matches = readers
            .iter()
            .filter(|r| r.to_string_lossy().to_ascii_lowercase().contains(&wanted))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [] => bail!("no PC/SC reader matches {selector:?}"),
            [one] => Ok(*one),
            many => bail!(
                "{} PC/SC readers match {selector:?}; use a more specific --reader value",
                many.len()
            ),
        };
    }

    if readers.len() == 1 {
        return Ok(&readers[0]);
    }
    let rutokens = readers
        .iter()
        .filter(|r| r.to_string_lossy().to_ascii_lowercase().contains("rutoken"))
        .collect::<Vec<_>>();
    match rutokens.as_slice() {
        [one] => Ok(*one),
        _ => {
            let names = readers
                .iter()
                .map(|r| format!("  {}", r.to_string_lossy()))
                .collect::<Vec<_>>()
                .join("\n");
            bail!("multiple PC/SC readers found; specify --reader:\n{names}")
        }
    }
}

fn read_access_from_sec_attr(sec_attr: &[u8]) -> ReadAccess {
    // Rutoken ECP/Lite driver (OpenSC card-rtecp.c):
    // sec_attr[0] is AccessMode. For EFs, bit 0 means a READ condition is
    // present and sec_attr[1] is that condition: 0=none, 1=CHV1, 2=CHV2,
    // FF=never. Other values are deliberately not guessed.
    if sec_attr.is_empty() || (sec_attr[0] & 0x01) == 0 {
        return ReadAccess::NotSpecified;
    }
    if sec_attr.len() < 2 {
        return ReadAccess::Unknown(0xFE);
    }
    match sec_attr[1] {
        0x00 => ReadAccess::None,
        0x01 => ReadAccess::Chv(1),
        0x02 => ReadAccess::Chv(2),
        0xFF => ReadAccess::Never,
        value => ReadAccess::Unknown(value),
    }
}

fn parse_fcp(data: &[u8]) -> Result<FcpInfo> {
    if data.is_empty() {
        bail!("empty FCP response");
    }
    let fid_raw = find_tlv_recursive(data, 0x83);
    let size_raw = find_tlv_recursive(data, 0x80);
    let descriptor_raw = find_tlv_recursive(data, 0x82);
    let sec_attr_raw = find_tlv_recursive(data, 0x86);

    let fid = match fid_raw {
        Some(v) if v.len() == 2 => Some(u16::from_be_bytes([v[0], v[1]])),
        Some(v) => bail!("FCP tag 0x83 has {} bytes, expected 2", v.len()),
        None => None,
    };
    let size = match size_raw {
        Some(v) if v.len() == 2 => Some(u16::from_be_bytes([v[0], v[1]]) as usize),
        Some(v) if v.len() == 1 => Some(v[0] as usize),
        Some(v) => bail!("FCP tag 0x80 has unsupported length {}", v.len()),
        None => None,
    };
    let descriptor = descriptor_raw.and_then(|v| v.first()).copied();

    Ok(FcpInfo {
        fid,
        size,
        descriptor,
        sec_attr: sec_attr_raw.unwrap_or(&[]).to_vec(),
        raw: data.to_vec(),
    })
}

fn find_tlv_recursive<'a>(data: &'a [u8], wanted: u8) -> Option<&'a [u8]> {
    let mut offset = 0usize;
    while offset + 2 <= data.len() {
        let tag = data[offset];
        offset += 1;
        let (len, len_bytes) = parse_ber_len(data.get(offset..)?)?;
        offset += len_bytes;
        let end = offset.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        let value = &data[offset..end];
        if tag == wanted {
            return Some(value);
        }
        if tag & 0x20 != 0 {
            if let Some(found) = find_tlv_recursive(value, wanted) {
                return Some(found);
            }
        }
        offset = end;
    }
    None
}

fn parse_ber_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 4 || data.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for b in &data[1..1 + count] {
        len = len.checked_mul(256)?.checked_add(*b as usize)?;
    }
    Some((len, 1 + count))
}

fn check_sw(op: &str, sw: u16) -> Result<()> {
    if sw == SW_OK {
        return Ok(());
    }
    let meaning = match sw {
        0x6300 => "authentication failed",
        0x6700 => "wrong length",
        0x6982 => "security status not satisfied",
        0x6983 => "authentication method blocked",
        0x6985 => "command not allowed",
        0x6986 => "no current EF selected",
        0x6A80 => "invalid data parameters",
        0x6A81 => "function/mode not supported",
        0x6A82 => "file not found",
        0x6A86 => "invalid P1/P2",
        0x6B00 => "offset beyond file",
        0x6D00 => "instruction not supported",
        0x6F84 => "Rutoken busy",
        _ if sw & 0xfff0 == 0x63c0 => "PIN authentication failed (retry counter in SW2)",
        _ if sw & 0xff00 == 0x6c00 => "wrong Le (correct length encoded in SW2)",
        _ => "unknown card status",
    };
    bail!("{op}: Rutoken SW={sw:04X} ({meaning})")
}

pub fn parse_path(text: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for piece in text
        .split(|c| c == '/' || c == '\\' || c == ':')
        .filter(|s| !s.is_empty())
    {
        let piece = piece
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        if piece.len() > 4 || piece.is_empty() {
            bail!("invalid FID {piece:?} in path {text:?}");
        }
        out.push(
            u16::from_str_radix(piece, 16).with_context(|| format!("invalid hex FID {piece:?}"))?,
        );
    }
    if out.is_empty() {
        bail!("empty Rutoken path");
    }
    Ok(out)
}

pub fn format_path(path: &[u16]) -> String {
    path.iter()
        .map(|v| format!("{v:04X}"))
        .collect::<Vec<_>>()
        .join("/")
}

pub fn format_fid_set(ids: &BTreeSet<u16>) -> String {
    ids.iter()
        .map(|v| format!("{v:04X}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn logical_ef_id(_path: &[u16], physical_fid: u16) -> Option<u16> {
    let suffix = physical_fid & 0x00ff;
    if (1..=6).contains(&suffix) {
        Some(suffix)
    } else {
        None
    }
}

fn logical_ef_set(path: &[u16], physical_ids: &BTreeSet<u16>) -> BTreeSet<u16> {
    physical_ids
        .iter()
        .filter_map(|fid| logical_ef_id(path, *fid))
        .collect()
}

pub fn classic_ef_name_at_path(path: &[u16]) -> Option<&'static str> {
    if path.len() < 2 {
        return None;
    }
    let physical = *path.last()?;
    let parent = &path[..path.len() - 1];
    let logical = logical_ef_id(parent, physical)?;
    classic_ef_name(logical)
}

pub fn classic_ef_name(logical_fid: u16) -> Option<&'static str> {
    match logical_fid {
        0x0001 => Some("masks.key"),
        0x0002 => Some("primary.key"),
        0x0003 => Some("header.key"),
        0x0004 => Some("masks2.key"),
        0x0005 => Some("primary2.key"),
        0x0006 => Some("name.key"),
        _ => None,
    }
}

pub fn classic_all_efs() -> &'static [u16] {
    &CLASSIC_ALL_EFS
}
