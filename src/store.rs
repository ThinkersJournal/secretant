// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `Store` trait and the local encrypted file store (`FileStore`).
//!
//! File format 1 (JSON, so a person can see what is in it and that nothing is
//! readable): a random 256-bit *data key* encrypts all entries with
//! XChaCha20-Poly1305; the data key is wrapped by a passphrase wrap (key derived
//! with Argon2id). The wrap list holds more than one wrap, so later slices add
//! recovery-key and OS-bound wraps without a format change.
//!
//! Errors carry a class and never any store text, name or value.
//!
//! Limit stated once: the wipe of secret bytes is best effort. The decrypted
//! payload and the hex text it passes through are wiped when dropped, but the
//! allocator may have moved them first.

use crate::value::SecretValue;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const FORMAT: u32 = 1;
const AAD_DATA: &[u8] = b"secretant-1-data";
const AAD_WRAP: &[u8] = b"secretant-1-wrap";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const SALT_LEN: usize = 16;

/// Why an operation failed. Never carries a name, a value or file text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// No entry with that name.
    NotFound,
    /// The passphrase did not open the store (or the wrap was altered: the
    /// cipher cannot tell the two apart).
    WrongPassphrase,
    /// The file is not a valid store or was altered; nothing was returned.
    Corrupt,
    /// The file declares a format this version does not read.
    UnsupportedFormat,
    /// The recovery key did not open the store (or is not a recovery key).
    WrongRecoveryKey,
    /// The OS-bound wrap did not open the store: none present, a different
    /// user or machine, or this platform has no such wrap.
    OsWrapFailed,
    /// `create` found a file already there.
    AlreadyExists,
    /// `open` found no file.
    NoSuchStore,
    /// An import would overwrite names already in the store and no choice was made.
    Conflict,
    /// The name is empty or has a control character.
    BadName,
    /// The operating system refused a file operation.
    Io,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            StoreError::NotFound => "no such entry",
            StoreError::WrongPassphrase => "the passphrase did not open the store",
            StoreError::Corrupt => "the store file is damaged or was altered",
            StoreError::UnsupportedFormat => "the store file has a format this version cannot read",
            StoreError::WrongRecoveryKey => "the recovery key did not open the store",
            StoreError::OsWrapFailed => {
                "the operating system could not open the store for this user"
            }
            StoreError::AlreadyExists => "a store already exists at that path",
            StoreError::NoSuchStore => "no store at that path",
            StoreError::Conflict => {
                "the import would overwrite existing names; choose to keep or replace them"
            }
            StoreError::BadName => "the name is empty or contains a control character",
            StoreError::Io => "a file operation failed",
        })
    }
}

impl std::error::Error for StoreError {}

/// Non-secret facts about an entry. Never includes a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    /// Latest version number (the first put is version 1).
    pub latest: u32,
    /// How many versions are kept.
    pub versions: u32,
    /// When the latest version was written, seconds since the Unix epoch.
    pub updated_unix: u64,
    /// Non-secret metadata of the latest version. Callers must not put secrets here.
    pub metadata: BTreeMap<String, String>,
}

/// What an application can do with a store.
pub trait Store {
    /// Add a new version of `name` (creating the entry on first use). Returns the
    /// version number. `metadata` is stored in the clear inside the encrypted
    /// payload and shown by `describe`; it must not hold a secret.
    fn put(
        &mut self,
        name: &str,
        value: SecretValue,
        metadata: BTreeMap<String, String>,
    ) -> Result<u32, StoreError>;
    /// The latest value of `name`.
    fn get(&self, name: &str) -> Result<SecretValue, StoreError>;
    /// A given version's value.
    fn get_version(&self, name: &str, version: u32) -> Result<SecretValue, StoreError>;
    /// Every name, sorted.
    fn list(&self) -> Vec<String>;
    /// Non-secret facts about `name`.
    fn describe(&self, name: &str) -> Result<EntryInfo, StoreError>;
}

/// What to do with a name that is in both the store and an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportConflict {
    /// Stop before writing anything.
    Refuse,
    /// Leave the store's entry as it is.
    Keep,
    /// Add the bundle's latest value as a new version (nothing is deleted).
    Replace,
}

/// One line of an import plan. A name, never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportItem {
    /// The entry name.
    pub name: String,
    /// The store already has this name.
    pub exists: bool,
    /// How many versions the bundle holds for it.
    pub versions: u32,
}

/// What an import did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ImportReport {
    /// Names added with all their versions.
    pub added: u32,
    /// Names whose latest value was added as a new version.
    pub replaced: u32,
    /// Names left as they were.
    pub kept: u32,
}

/// The plain, unencrypted header of a store file: no secret is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspection {
    /// The file format number.
    pub format: u32,
    /// Each wrap's kind and, for a passphrase wrap, its Argon2id cost.
    pub wraps: Vec<(String, Option<KdfParams>)>,
}

/// Argon2id cost parameters, recorded in the file so a later version can raise them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane: above the OWASP floor for Argon2id.
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

impl KdfParams {
    // A file may ask for costs; refuse absurd ones so a hostile file cannot
    // make `open` exhaust memory or run for hours.
    fn acceptable(&self) -> bool {
        self.p >= 1
            && self.p <= 16
            && self.t >= 1
            && self.t <= 20
            && self.m_kib >= 8 * self.p
            && self.m_kib <= 1024 * 1024
    }
}

// ---- hex ----

fn to_hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 15) as usize] as char);
    }
    s
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    let t = text.as_bytes();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    t.chunks(2)
        .map(|p| Some(nib(p[0])? << 4 | nib(p[1])?))
        .collect()
}

mod hexbytes {
    use super::{from_hex, to_hex};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(v: &Zeroizing<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(to_hex(v));
        s.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        from_hex(&text)
            .map(Zeroizing::new)
            .ok_or_else(|| D::Error::custom("bad hex"))
    }
}

// ---- payload (what is encrypted) ----

#[derive(Serialize, Deserialize)]
struct Version {
    v: u32,
    at: u64,
    #[serde(with = "hexbytes")]
    value: Zeroizing<Vec<u8>>,
    meta: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Contents {
    entries: BTreeMap<String, Vec<Version>>,
}

// ---- file (what is on disk) ----

/// One way to unlock the data key. `kind` is "passphrase" (Argon2id key seals the
/// data key), "recovery" (a random 256-bit key seals it) or "os-dpapi" (Windows
/// DPAPI seals it for this user; `wrapped` is the DPAPI blob).
#[derive(Clone, Serialize, Deserialize)]
struct Wrap {
    kind: String,
    #[serde(default)]
    salt: String,
    #[serde(default)]
    kdf: Option<KdfParams>,
    #[serde(default)]
    nonce: String,
    wrapped: String,
}

#[derive(Serialize, Deserialize)]
struct FileImage {
    format: u32,
    wraps: Vec<Wrap>,
    nonce: String,
    ciphertext: String,
}

fn random<const N: usize>() -> Result<[u8; N], StoreError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| StoreError::Io)?;
    Ok(b)
}

fn derive(
    passphrase: &SecretValue,
    salt: &[u8],
    p: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    let params =
        argon2::Params::new(p.m_kib, p.t, p.p, Some(KEY_LEN)).map_err(|_| StoreError::Corrupt)?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    a.hash_password_into(passphrase.expose(), salt, out.as_mut())
        .map_err(|_| StoreError::Corrupt)?;
    Ok(out)
}

fn seal(key: &[u8], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, StoreError> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|_| StoreError::Corrupt)?;
    let n = XNonce::try_from(nonce).map_err(|_| StoreError::Corrupt)?;
    c.encrypt(&n, Payload { msg: plain, aad })
        .map_err(|_| StoreError::Corrupt)
}

fn unseal(key: &[u8], nonce: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let c = XChaCha20Poly1305::new_from_slice(key).ok()?;
    let n = XNonce::try_from(nonce).ok()?;
    c.decrypt(&n, Payload { msg: sealed, aad })
        .ok()
        .map(Zeroizing::new)
}

/// What opens a store.
pub enum Unlock<'a> {
    /// The person's passphrase.
    Passphrase(&'a SecretValue),
    /// The recovery key text shown once at creation.
    Recovery(&'a SecretValue),
    /// The operating system, as the same user on the same machine (Windows DPAPI).
    Os,
}

impl Unlock<'_> {
    fn failure(&self) -> StoreError {
        match self {
            Unlock::Passphrase(_) => StoreError::WrongPassphrase,
            Unlock::Recovery(_) => StoreError::WrongRecoveryKey,
            Unlock::Os => StoreError::OsWrapFailed,
        }
    }
}

fn data_key_from(k: &[u8]) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    if k.len() != KEY_LEN {
        return None;
    }
    let mut arr = Zeroizing::new([0u8; KEY_LEN]);
    arr.copy_from_slice(k);
    Some(arr)
}

/// Try one wrap with the offered unlock. `Ok(None)` means "not this wrap, or the
/// key did not fit"; `Err` means the file itself is damaged.
fn try_wrap(w: &Wrap, unlock: &Unlock<'_>) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>, StoreError> {
    match (w.kind.as_str(), unlock) {
        ("passphrase", Unlock::Passphrase(pass)) => {
            let Some(kdf) = w.kdf.filter(KdfParams::acceptable) else {
                return Ok(None);
            };
            let (Some(salt), Some(nonce), Some(wrapped)) =
                (from_hex(&w.salt), from_hex(&w.nonce), from_hex(&w.wrapped))
            else {
                return Err(StoreError::Corrupt);
            };
            let wk = derive(pass, &salt, &kdf)?;
            Ok(unseal(wk.as_ref(), &nonce, AAD_WRAP, &wrapped).and_then(|k| data_key_from(&k)))
        }
        ("recovery", Unlock::Recovery(text)) => {
            let Some(key) = parse_recovery(text) else {
                return Ok(None);
            };
            let (Some(nonce), Some(wrapped)) = (from_hex(&w.nonce), from_hex(&w.wrapped)) else {
                return Err(StoreError::Corrupt);
            };
            Ok(unseal(key.as_ref(), &nonce, AAD_WRAP, &wrapped).and_then(|k| data_key_from(&k)))
        }
        ("os-dpapi", Unlock::Os) => {
            let Some(blob) = from_hex(&w.wrapped) else {
                return Err(StoreError::Corrupt);
            };
            Ok(os::unprotect(&blob).and_then(|k| data_key_from(&k)))
        }
        _ => Ok(None),
    }
}

/// Recovery key text: 64 hex digits in groups of 8 joined by `-`.
fn format_recovery(key: &[u8]) -> String {
    to_hex(key)
        .as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("-")
}

fn parse_recovery(text: &SecretValue) -> Option<Zeroizing<Vec<u8>>> {
    let raw = std::str::from_utf8(text.expose()).ok()?;
    let compact: Zeroizing<String> = Zeroizing::new(
        raw.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect(),
    );
    from_hex(&compact)
        .filter(|k| k.len() == KEY_LEN)
        .map(Zeroizing::new)
}

/// Create a file only its owner can read: `0600` on Unix; on Windows the ACL is
/// reduced to the current user right after creation (see `os::restrict`).
fn create_private(path: &Path) -> Result<fs::File, StoreError> {
    #[cfg(unix)]
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    };
    #[cfg(not(unix))]
    let f = fs::File::create(path);
    let f = f.map_err(|_| StoreError::Io)?;
    os::restrict(path)?;
    Ok(f)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn check_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        Err(StoreError::BadName)
    } else {
        Ok(())
    }
}

/// The local encrypted store: one file, opened with a passphrase.
pub struct FileStore {
    path: PathBuf,
    data_key: Zeroizing<[u8; KEY_LEN]>,
    wraps: Vec<Wrap>,
    payload: Contents,
}

impl fmt::Debug for FileStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileStore(<redacted>)")
    }
}

impl FileStore {
    /// Create a new, empty store at `path` with a passphrase wrap. Refuses to
    /// overwrite an existing file.
    pub fn create(path: impl AsRef<Path>, passphrase: &SecretValue) -> Result<Self, StoreError> {
        Self::create_with_params(path, passphrase, KdfParams::default())
    }

    /// As [`FileStore::create`] with explicit Argon2id costs.
    pub fn create_with_params(
        path: impl AsRef<Path>,
        passphrase: &SecretValue,
        kdf: KdfParams,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(StoreError::AlreadyExists);
        }
        if !kdf.acceptable() {
            return Err(StoreError::Corrupt);
        }
        let data_key = Zeroizing::new(random::<KEY_LEN>()?);
        let salt = random::<SALT_LEN>()?;
        let nonce = random::<NONCE_LEN>()?;
        let wrap_key = derive(passphrase, &salt, &kdf)?;
        let wrapped = seal(wrap_key.as_ref(), &nonce, AAD_WRAP, data_key.as_ref())?;
        let wrap = Wrap {
            kind: "passphrase".into(),
            salt: to_hex(&salt),
            kdf: Some(kdf),
            nonce: to_hex(&nonce),
            wrapped: to_hex(&wrapped),
        };
        let store = Self {
            path,
            data_key,
            wraps: vec![wrap],
            payload: Contents::default(),
        };
        store.save()?;
        Ok(store)
    }

    /// Open an existing store with its passphrase.
    pub fn open(path: impl AsRef<Path>, passphrase: &SecretValue) -> Result<Self, StoreError> {
        Self::open_with(path, Unlock::Passphrase(passphrase))
    }

    /// Open an existing store with any one of its wraps. Several wraps open the
    /// same data key, so losing one does not lose the store.
    pub fn open_with(path: impl AsRef<Path>, unlock: Unlock<'_>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NoSuchStore);
            }
            Err(_) => return Err(StoreError::Io),
        };
        let image: FileImage = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if image.format != FORMAT {
            return Err(StoreError::UnsupportedFormat);
        }
        let mut data_key: Option<Zeroizing<[u8; KEY_LEN]>> = None;
        for w in &image.wraps {
            if let Some(k) = try_wrap(w, &unlock)? {
                data_key = Some(k);
                break;
            }
        }
        let data_key = data_key.ok_or(unlock.failure())?;
        let (Some(nonce), Some(sealed)) = (from_hex(&image.nonce), from_hex(&image.ciphertext))
        else {
            return Err(StoreError::Corrupt);
        };
        let plain =
            unseal(data_key.as_ref(), &nonce, AAD_DATA, &sealed).ok_or(StoreError::Corrupt)?;
        let payload: Contents = serde_json::from_slice(&plain).map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            path,
            data_key,
            wraps: image.wraps,
            payload,
        })
    }

    /// Add a recovery wrap and return the recovery key, to be shown to the person
    /// once ("write this down"). It is not stored anywhere in readable form:
    /// whoever holds it holds the store.
    pub fn add_recovery_wrap(&mut self) -> Result<SecretValue, StoreError> {
        let key = Zeroizing::new(random::<KEY_LEN>()?);
        let nonce = random::<NONCE_LEN>()?;
        let wrapped = seal(key.as_ref(), &nonce, AAD_WRAP, self.data_key.as_ref())?;
        let text = format_recovery(key.as_ref());
        self.push_wrap(Wrap {
            kind: "recovery".into(),
            salt: String::new(),
            kdf: None,
            nonce: to_hex(&nonce),
            wrapped: to_hex(&wrapped),
        })?;
        Ok(SecretValue::from_string(text))
    }

    /// Add an OS-bound wrap so this user, on this machine, opens the store with
    /// no password (an unattended program). Windows only for now; other systems
    /// get `OsWrapFailed`. Any process running as the same user can ask: that is
    /// the stated limit of this wrap.
    pub fn add_os_wrap(&mut self) -> Result<(), StoreError> {
        let blob = os::protect(self.data_key.as_ref()).ok_or(StoreError::OsWrapFailed)?;
        self.push_wrap(Wrap {
            kind: "os-dpapi".into(),
            salt: String::new(),
            kdf: None,
            nonce: String::new(),
            wrapped: to_hex(&blob),
        })
    }

    /// Which kinds of wrap the file has (not secret).
    pub fn wrap_kinds(&self) -> Vec<String> {
        self.wraps.iter().map(|w| w.kind.clone()).collect()
    }

    /// Read the unencrypted header of the store file at `path` without
    /// unlocking it: the format and the wraps. Fails for a file that is not a
    /// store of a format this version reads.
    pub fn inspect(path: impl AsRef<Path>) -> Result<Inspection, StoreError> {
        let bytes = match fs::read(path.as_ref()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NoSuchStore);
            }
            Err(_) => return Err(StoreError::Io),
        };
        let image: FileImage = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if image.format != FORMAT {
            return Err(StoreError::UnsupportedFormat);
        }
        if from_hex(&image.nonce).is_none() || from_hex(&image.ciphertext).is_none() {
            return Err(StoreError::Corrupt);
        }
        Ok(Inspection {
            format: image.format,
            wraps: image
                .wraps
                .iter()
                .map(|w| (w.kind.clone(), w.kdf))
                .collect(),
        })
    }

    /// When version `version` of `name` was written, and its non-secret metadata.
    pub fn version_info(
        &self,
        name: &str,
        version: u32,
    ) -> Result<(u64, BTreeMap<String, String>), StoreError> {
        let v = self
            .versions(name)?
            .iter()
            .find(|x| x.v == version)
            .ok_or(StoreError::NotFound)?;
        Ok((v.at, v.meta.clone()))
    }

    /// Copy every entry, every version and its metadata into `bundle`, which
    /// must be empty (a store just created with the bundle's own passphrase).
    /// The export bundle is a store file with one passphrase wrap: its format is
    /// the store format, documented in `docs/DESIGN.md`.
    pub fn export_to(&self, bundle: &mut FileStore) -> Result<(), StoreError> {
        if !bundle.payload.entries.is_empty() {
            return Err(StoreError::AlreadyExists);
        }
        for (name, list) in &self.payload.entries {
            let copy = list
                .iter()
                .map(|v| Version {
                    v: v.v,
                    at: v.at,
                    value: v.value.clone(),
                    meta: v.meta.clone(),
                })
                .collect();
            bundle.payload.entries.insert(name.clone(), copy);
        }
        bundle.save()
    }

    /// What importing `src` into this store would do. Reads, writes nothing.
    pub fn plan_import(&self, src: &FileStore) -> Vec<ImportItem> {
        src.payload
            .entries
            .iter()
            .map(|(name, list)| ImportItem {
                name: name.clone(),
                exists: self.payload.entries.contains_key(name),
                versions: u32::try_from(list.len()).unwrap_or(u32::MAX),
            })
            .collect()
    }

    /// Merge `src` into this store in memory and write once. New names come with
    /// all their versions, numbers, times and metadata. A name already here is
    /// refused, kept, or given the bundle's latest value as a NEW version,
    /// according to `conflict`; nothing is ever deleted or overwritten. With
    /// [`ImportConflict::Refuse`] and any conflict, nothing is written.
    pub fn apply_import(
        &mut self,
        src: &FileStore,
        conflict: ImportConflict,
    ) -> Result<ImportReport, StoreError> {
        if conflict == ImportConflict::Refuse
            && src
                .payload
                .entries
                .keys()
                .any(|n| self.payload.entries.contains_key(n))
        {
            return Err(StoreError::Conflict);
        }
        let backup: BTreeMap<String, Vec<Version>> = self
            .payload
            .entries
            .iter()
            .map(|(n, l)| {
                let copy = l
                    .iter()
                    .map(|v| Version {
                        v: v.v,
                        at: v.at,
                        value: v.value.clone(),
                        meta: v.meta.clone(),
                    })
                    .collect();
                (n.clone(), copy)
            })
            .collect();
        let mut report = ImportReport::default();
        for (name, list) in &src.payload.entries {
            check_name(name)?;
            match self.payload.entries.get_mut(name) {
                None => {
                    let copy = list
                        .iter()
                        .map(|v| Version {
                            v: v.v,
                            at: v.at,
                            value: v.value.clone(),
                            meta: v.meta.clone(),
                        })
                        .collect();
                    self.payload.entries.insert(name.clone(), copy);
                    report.added += 1;
                }
                Some(_) if conflict == ImportConflict::Keep => report.kept += 1,
                Some(mine) => {
                    let Some(latest) = list.last() else { continue };
                    let next = mine.last().map_or(1, |l| l.v + 1);
                    mine.push(Version {
                        v: next,
                        at: now_unix(),
                        value: latest.value.clone(),
                        meta: latest.meta.clone(),
                    });
                    report.replaced += 1;
                }
            }
        }
        if let Err(e) = self.save() {
            // Keep memory and disk the same.
            self.payload.entries = backup;
            return Err(e);
        }
        Ok(report)
    }

    fn push_wrap(&mut self, w: Wrap) -> Result<(), StoreError> {
        self.wraps.push(w);
        if let Err(e) = self.save() {
            self.wraps.pop();
            return Err(e);
        }
        Ok(())
    }

    /// Write the whole store: new file beside the old one, flushed, then renamed
    /// into place, keeping the previous generation as `<path>.prev`.
    fn save(&self) -> Result<(), StoreError> {
        let nonce = random::<NONCE_LEN>()?;
        let plain =
            Zeroizing::new(serde_json::to_vec(&self.payload).map_err(|_| StoreError::Corrupt)?);
        let sealed = seal(self.data_key.as_ref(), &nonce, AAD_DATA, &plain)?;
        let wraps = self.wraps.clone();
        let image = FileImage {
            format: FORMAT,
            wraps,
            nonce: to_hex(&nonce),
            ciphertext: to_hex(&sealed),
        };
        let text = serde_json::to_vec_pretty(&image).map_err(|_| StoreError::Corrupt)?;
        let tmp = sibling(&self.path, "tmp");
        let prev = sibling(&self.path, "prev");
        let mut f = create_private(&tmp)?;
        f.write_all(&text).map_err(|_| StoreError::Io)?;
        f.sync_all().map_err(|_| StoreError::Io)?;
        drop(f);
        if self.path.exists() {
            // Replace the previous generation with the current file.
            let _ = fs::remove_file(&prev);
            fs::rename(&self.path, &prev).map_err(|_| StoreError::Io)?;
        }
        fs::rename(&tmp, &self.path).map_err(|_| StoreError::Io)?;
        Ok(())
    }

    fn versions(&self, name: &str) -> Result<&Vec<Version>, StoreError> {
        self.payload.entries.get(name).ok_or(StoreError::NotFound)
    }
}

fn sibling(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// Write `bytes` to `path` so only the owner can read it, atomically: a private
/// temporary file beside it, flushed, then renamed over the target. A failure
/// leaves the old file as it was.
pub(crate) fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = sibling(path, "tmp");
    let mut f = create_private(&tmp)?;
    let done = f.write_all(bytes).and_then(|_| f.sync_all());
    drop(f);
    if done.is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(StoreError::Io);
    }
    if fs::rename(&tmp, path).is_err() {
        let _ = fs::remove_file(&tmp);
        return Err(StoreError::Io);
    }
    Ok(())
}

/// Is `path` readable by its owner only? `false` on any doubt.
pub(crate) fn is_private(path: &Path) -> bool {
    os::is_private(path)
}

/// Platform-bound pieces: DPAPI and the owner-only ACL.
mod os {
    use super::StoreError;
    use std::path::Path;

    #[cfg(windows)]
    const ENTROPY: &[u8] = b"secretant-1-os-wrap";

    #[cfg(windows)]
    pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
        };
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let ent = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: pointers are valid for the call; DPAPI allocates `out`, which is
        // copied and freed below.
        unsafe {
            if CryptProtectData(
                &input,
                std::ptr::null(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                return None;
            }
            let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
            LocalFree(out.pbData as _);
            Some(v)
        }
    }

    #[cfg(windows)]
    pub fn unprotect(blob: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        };
        let input = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let ent = CRYPT_INTEGER_BLOB {
            cbData: ENTROPY.len() as u32,
            pbData: ENTROPY.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`; the plaintext buffer is wiped before it is freed.
        unsafe {
            if CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &ent,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            ) == 0
            {
                return None;
            }
            let slice = std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize);
            let v = zeroize::Zeroizing::new(slice.to_vec());
            zeroize::Zeroize::zeroize(slice);
            LocalFree(out.pbData as _);
            Some(v)
        }
    }

    #[cfg(not(windows))]
    pub fn protect(_data: &[u8]) -> Option<Vec<u8>> {
        None
    }

    #[cfg(not(windows))]
    pub fn unprotect(_blob: &[u8]) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        None
    }

    /// Windows: true when the ACL lists no principal but the current user.
    #[cfg(windows)]
    pub fn is_private(path: &Path) -> bool {
        use std::process::Command;
        let Ok(user) = std::env::var("USERNAME") else {
            return false;
        };
        let Some(listing) = Command::new("icacls")
            .arg(path)
            .output()
            .ok()
            .filter(|o| o.status.success())
        else {
            return false;
        };
        let text = String::from_utf8_lossy(&listing.stdout).into_owned();
        let prefix = path.to_string_lossy().into_owned();
        let me = user.to_lowercase();
        let mut seen_me = false;
        for line in text.lines() {
            let Some(end) = line.find(":(") else { continue };
            let head = line[..end].trim();
            let name = head.strip_prefix(prefix.as_str()).unwrap_or(head).trim();
            if name.is_empty() {
                continue;
            }
            if name.to_lowercase().ends_with(&me) {
                seen_me = true;
            } else {
                return false;
            }
        }
        seen_me
    }

    /// Windows: remove inherited access, grant the current user, then remove every
    /// other principal that still holds an explicit entry (an administrator's
    /// token adds its own defaults), and read the ACL back.
    #[cfg(windows)]
    pub fn restrict(path: &Path) -> Result<(), StoreError> {
        use std::process::Command;
        let user = std::env::var("USERNAME").map_err(|_| StoreError::Io)?;
        let who = match std::env::var("USERDOMAIN") {
            Ok(d) if !d.is_empty() => format!("{d}\\{user}"),
            _ => user.clone(),
        };
        let run = |args: &[&std::ffi::OsStr]| {
            Command::new("icacls")
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
        };
        let p = path.as_os_str();
        let grant = std::ffi::OsString::from(format!("{who}:(F)"));
        run(&[
            p,
            "/inheritance:r".as_ref(),
            "/grant:r".as_ref(),
            grant.as_os_str(),
        ])
        .ok_or(StoreError::Io)?;
        let listing = run(&[p]).ok_or(StoreError::Io)?;
        let text = String::from_utf8_lossy(&listing.stdout).into_owned();
        let prefix = path.to_string_lossy().into_owned();
        let me = user.to_lowercase();
        for line in text.lines() {
            let Some(end) = line.find(":(") else { continue };
            let head = line[..end].trim();
            let name = head.strip_prefix(prefix.as_str()).unwrap_or(head).trim();
            if name.is_empty() || name.to_lowercase().ends_with(&me) {
                continue;
            }
            run(&[p, "/remove:g".as_ref(), name.as_ref()]).ok_or(StoreError::Io)?;
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub fn restrict(_path: &Path) -> Result<(), StoreError> {
        Ok(()) // created 0600 already
    }

    #[cfg(not(windows))]
    pub fn is_private(path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o077 == 0)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }
}

impl Store for FileStore {
    fn put(
        &mut self,
        name: &str,
        value: SecretValue,
        metadata: BTreeMap<String, String>,
    ) -> Result<u32, StoreError> {
        check_name(name)?;
        let list = self.payload.entries.entry(name.to_string()).or_default();
        let v = list.last().map_or(1, |l| l.v + 1);
        list.push(Version {
            v,
            at: now_unix(),
            value: Zeroizing::new(value.expose().to_vec()),
            meta: metadata,
        });
        if let Err(e) = self.save() {
            // Keep memory and disk the same: undo the in-memory add.
            let list = self.payload.entries.get_mut(name);
            if let Some(list) = list {
                list.pop();
                if list.is_empty() {
                    self.payload.entries.remove(name);
                }
            }
            return Err(e);
        }
        Ok(v)
    }

    fn get(&self, name: &str) -> Result<SecretValue, StoreError> {
        let last = self.versions(name)?.last().ok_or(StoreError::NotFound)?;
        Ok(SecretValue::new(last.value.to_vec()))
    }

    fn get_version(&self, name: &str, version: u32) -> Result<SecretValue, StoreError> {
        let found = self
            .versions(name)?
            .iter()
            .find(|x| x.v == version)
            .ok_or(StoreError::NotFound)?;
        Ok(SecretValue::new(found.value.to_vec()))
    }

    fn list(&self) -> Vec<String> {
        self.payload.entries.keys().cloned().collect()
    }

    fn describe(&self, name: &str) -> Result<EntryInfo, StoreError> {
        let vs = self.versions(name)?;
        let last = vs.last().ok_or(StoreError::NotFound)?;
        Ok(EntryInfo {
            latest: last.v,
            versions: vs.len() as u32,
            updated_unix: last.at,
            metadata: last.meta.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "hunter2-canary-store";
    const FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    fn pass(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn new_store(dir: &tempfile::TempDir) -> FileStore {
        FileStore::create_with_params(dir.path().join("s.secretant"), &pass("pw"), FAST).unwrap()
    }

    #[test]
    fn put_get_list_describe_round_trip_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        {
            let mut s = new_store(&dir);
            let mut meta = BTreeMap::new();
            meta.insert("purpose".to_string(), "db".to_string());
            assert_eq!(
                s.put("A", SecretValue::from_string(CANARY.into()), meta)
                    .unwrap(),
                1
            );
            assert_eq!(
                s.put("A", SecretValue::from_string("two".into()), BTreeMap::new())
                    .unwrap(),
                2
            );
            s.put("B", SecretValue::from_string("b".into()), BTreeMap::new())
                .unwrap();
        }
        let s = FileStore::open(&path, &pass("pw")).unwrap();
        assert_eq!(s.list(), vec!["A".to_string(), "B".to_string()]);
        assert!(s.get("A").unwrap().expose() == b"two");
        assert!(s.get_version("A", 1).unwrap().expose() == CANARY.as_bytes());
        let d = s.describe("A").unwrap();
        assert_eq!((d.latest, d.versions), (2, 2));
        assert_eq!(s.get("Z").err(), Some(StoreError::NotFound));
        assert_eq!(s.get_version("A", 9).err(), Some(StoreError::NotFound));
    }

    #[test]
    fn describe_carries_metadata_but_no_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        let mut meta = BTreeMap::new();
        meta.insert("purpose".to_string(), "db".to_string());
        s.put("A", SecretValue::from_string(CANARY.into()), meta)
            .unwrap();
        let d = s.describe("A").unwrap();
        assert_eq!(d.metadata.get("purpose").map(String::as_str), Some("db"));
        assert!(!format!("{d:?}").contains(CANARY));
    }

    #[test]
    fn canary_is_not_in_the_file_in_any_encoding_nor_in_formatting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        s.put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        assert!(!format!("{s:?}").contains(CANARY));
        for file in [path.clone(), sibling(&path, "prev")] {
            let bytes = fs::read(file).unwrap();
            let image: FileImage = serde_json::from_slice(&bytes).unwrap();
            // The file text, and the sealed field decoded once: the payload holds
            // the value as hex, so look for the raw and the hex form in both.
            let decoded = from_hex(&image.ciphertext).unwrap();
            for hay in [&bytes, &decoded] {
                assert!(!contains(hay, CANARY.as_bytes()));
                assert!(!contains(hay, to_hex(CANARY.as_bytes()).as_bytes()));
            }
        }
    }

    #[test]
    fn errors_never_show_the_canary_or_a_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put(
            CANARY,
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        let errs = [
            s.get(&format!("{CANARY}-missing")).err().unwrap(),
            FileStore::open(&path, &pass("wrong")).err().unwrap(),
        ];
        for e in errs {
            assert!(!format!("{e:?} {e}").contains(CANARY));
        }
    }

    #[test]
    fn wrong_passphrase_is_a_named_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        new_store(&dir);
        assert_eq!(
            FileStore::open(&path, &pass("nope")).err(),
            Some(StoreError::WrongPassphrase)
        );
    }

    #[test]
    fn every_flipped_byte_of_the_ciphertext_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        drop(s);
        let good = fs::read(&path).unwrap();
        let image: FileImage = serde_json::from_slice(&good).unwrap();
        let sealed = from_hex(&image.ciphertext).unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            let altered = FileImage {
                format: image.format,
                wraps: vec![],
                nonce: image.nonce.clone(),
                ciphertext: to_hex(&bad),
            };
            // Reuse the real wrap.
            let altered = FileImage {
                wraps: image
                    .wraps
                    .iter()
                    .map(|w| Wrap {
                        kind: w.kind.clone(),
                        salt: w.salt.clone(),
                        kdf: w.kdf,
                        nonce: w.nonce.clone(),
                        wrapped: w.wrapped.clone(),
                    })
                    .collect(),
                ..altered
            };
            fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert_eq!(
                FileStore::open(&path, &pass("pw")).err(),
                Some(StoreError::Corrupt),
                "byte {i}"
            );
        }
    }

    #[test]
    fn altered_nonce_or_wrap_or_garbage_is_an_error_never_a_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        drop(s);
        let good = fs::read_to_string(&path).unwrap();
        let image: FileImage = serde_json::from_str(&good).unwrap();
        // Flip one hex digit of the wrapped key.
        let mut w = from_hex(&image.wraps[0].wrapped).unwrap();
        w[0] ^= 1;
        let mut text = good.clone();
        text = text.replacen(&image.wraps[0].wrapped, &to_hex(&w), 1);
        assert_ne!(text, good, "mutation applied");
        fs::write(&path, &text).unwrap();
        assert!(FileStore::open(&path, &pass("pw")).is_err());
        fs::write(&path, b"not json at all").unwrap();
        assert_eq!(
            FileStore::open(&path, &pass("pw")).err(),
            Some(StoreError::Corrupt)
        );
        fs::write(
            &path,
            b"{\"format\":99,\"wraps\":[],\"nonce\":\"\",\"ciphertext\":\"\"}",
        )
        .unwrap();
        assert_eq!(
            FileStore::open(&path, &pass("pw")).err(),
            Some(StoreError::UnsupportedFormat)
        );
    }

    #[test]
    fn a_hostile_file_cannot_demand_absurd_kdf_cost() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        new_store(&dir);
        let good = fs::read_to_string(&path).unwrap();
        let image: FileImage = serde_json::from_str(&good).unwrap();
        let bad = good.replacen(
            &format!("\"m_kib\": {}", image.wraps[0].kdf.unwrap().m_kib),
            "\"m_kib\": 4000000000",
            1,
        );
        assert_ne!(bad, good, "mutation applied");
        fs::write(&path, bad).unwrap();
        assert_eq!(
            FileStore::open(&path, &pass("pw")).err(),
            Some(StoreError::WrongPassphrase)
        );
    }

    #[test]
    fn create_refuses_to_overwrite_and_open_reports_missing() {
        let dir = tempfile::tempdir().unwrap();
        new_store(&dir);
        let path = dir.path().join("s.secretant");
        assert_eq!(
            FileStore::create_with_params(&path, &pass("pw"), FAST).err(),
            Some(StoreError::AlreadyExists)
        );
        assert_eq!(
            FileStore::open(dir.path().join("none"), &pass("pw")).err(),
            Some(StoreError::NoSuchStore)
        );
    }

    #[test]
    fn bad_names_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        for n in ["", "a\nb", "a\u{0}b"] {
            assert_eq!(
                s.put(n, SecretValue::from_string("x".into()), BTreeMap::new())
                    .err(),
                Some(StoreError::BadName)
            );
        }
    }

    #[test]
    fn one_previous_generation_is_kept_and_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("one".into()), BTreeMap::new())
            .unwrap();
        s.put("A", SecretValue::from_string("two".into()), BTreeMap::new())
            .unwrap();
        let prev = FileStore::open(sibling(&path, "prev"), &pass("pw")).unwrap();
        assert!(prev.get("A").unwrap().expose() == b"one");
        assert!(!sibling(&path, "tmp").exists());
    }

    #[test]
    fn each_write_uses_a_fresh_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("x".into()), BTreeMap::new())
            .unwrap();
        let n1 = serde_json::from_slice::<FileImage>(&fs::read(&path).unwrap())
            .unwrap()
            .nonce;
        s.put("A", SecretValue::from_string("x".into()), BTreeMap::new())
            .unwrap();
        let n2 = serde_json::from_slice::<FileImage>(&fs::read(&path).unwrap())
            .unwrap()
            .nonce;
        assert_ne!(n1, n2);
    }

    fn drop_wraps_except(path: &Path, keep: &str) {
        let mut image: FileImage = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        image.wraps.retain(|w| w.kind == keep);
        assert_eq!(image.wraps.len(), 1, "exactly one wrap kept");
        fs::write(path, serde_json::to_vec(&image).unwrap()).unwrap();
    }

    fn other_recovery_key() -> SecretValue {
        let dir = tempfile::tempdir().unwrap();
        let mut s = FileStore::create_with_params(dir.path().join("o"), &pass("x"), FAST).unwrap();
        s.add_recovery_wrap().unwrap()
    }

    #[test]
    fn recovery_key_opens_and_is_not_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("v".into()), BTreeMap::new())
            .unwrap();
        let key = s.add_recovery_wrap().unwrap();
        assert!(format!("{key:?}").contains("redacted"));
        drop(s);
        let bytes = fs::read(&path).unwrap();
        assert!(!contains(&bytes, key.expose()));
        let compact: Vec<u8> = key
            .expose()
            .iter()
            .copied()
            .filter(|b| *b != b'-')
            .collect();
        assert!(!contains(&bytes, &compact));
        let s = FileStore::open_with(&path, Unlock::Recovery(&key)).unwrap();
        assert!(s.get("A").unwrap().expose() == b"v");
        // Pasted with spaces and capitals still works.
        let loose = SecretValue::from_string(
            std::str::from_utf8(key.expose())
                .unwrap()
                .replace('-', " ")
                .to_uppercase(),
        );
        assert!(FileStore::open_with(&path, Unlock::Recovery(&loose)).is_ok());
    }

    #[test]
    fn wrong_recovery_key_is_a_named_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        let key = s.add_recovery_wrap().unwrap();
        let other = other_recovery_key();
        assert_ne!(key.expose(), other.expose());
        for bad in [other, pass("short"), pass("")] {
            assert_eq!(
                FileStore::open_with(&path, Unlock::Recovery(&bad)).err(),
                Some(StoreError::WrongRecoveryKey)
            );
        }
    }

    #[test]
    fn losing_one_wrap_still_opens_through_another() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("v".into()), BTreeMap::new())
            .unwrap();
        let key = s.add_recovery_wrap().unwrap();
        drop(s);
        assert_eq!(
            FileStore::open(&path, &pass("pw")).unwrap().wrap_kinds(),
            vec!["passphrase".to_string(), "recovery".to_string()]
        );
        // Lose the passphrase wrap: the recovery key still opens it.
        let backup = fs::read(&path).unwrap();
        drop_wraps_except(&path, "recovery");
        assert_eq!(
            FileStore::open(&path, &pass("pw")).err(),
            Some(StoreError::WrongPassphrase)
        );
        assert!(FileStore::open_with(&path, Unlock::Recovery(&key)).is_ok());
        // Lose the recovery wrap: the passphrase still opens it.
        fs::write(&path, backup).unwrap();
        drop_wraps_except(&path, "passphrase");
        assert!(FileStore::open(&path, &pass("pw")).is_ok());
        assert_eq!(
            FileStore::open_with(&path, Unlock::Recovery(&key)).err(),
            Some(StoreError::WrongRecoveryKey)
        );
    }

    #[test]
    fn no_wrap_that_opens_is_a_named_error_for_each_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        new_store(&dir); // passphrase wrap only
        assert_eq!(
            FileStore::open_with(&path, Unlock::Os).err(),
            Some(StoreError::OsWrapFailed)
        );
        assert_eq!(
            FileStore::open_with(&path, Unlock::Recovery(&pass("a"))).err(),
            Some(StoreError::WrongRecoveryKey)
        );
    }

    #[test]
    fn adding_a_wrap_keeps_entries_and_the_same_data_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("v".into()), BTreeMap::new())
            .unwrap();
        let before = s.data_key.to_vec();
        s.add_recovery_wrap().unwrap();
        assert_eq!(before, s.data_key.to_vec());
        drop(s);
        assert!(
            FileStore::open(&path, &pass("pw"))
                .unwrap()
                .get("A")
                .is_ok()
        );
    }

    #[cfg(windows)]
    #[test]
    fn os_wrap_opens_for_this_user_with_no_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        s.add_os_wrap().unwrap();
        drop(s);
        let bytes = fs::read(&path).unwrap();
        assert!(!contains(&bytes, CANARY.as_bytes()));
        let s = FileStore::open_with(&path, Unlock::Os).unwrap();
        assert!(s.get("A").unwrap().expose() == CANARY.as_bytes());
        // A damaged blob does not open.
        let mut image: FileImage = serde_json::from_slice(&bytes).unwrap();
        for w in image.wraps.iter_mut().filter(|w| w.kind == "os-dpapi") {
            let mut b = from_hex(&w.wrapped).unwrap();
            let last = b.len() - 1;
            b[last] ^= 1;
            w.wrapped = to_hex(&b);
        }
        fs::write(&path, serde_json::to_vec(&image).unwrap()).unwrap();
        assert_eq!(
            FileStore::open_with(&path, Unlock::Os).err(),
            Some(StoreError::OsWrapFailed)
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn os_wrap_is_a_named_error_where_unsupported() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = new_store(&dir);
        assert_eq!(s.add_os_wrap().err(), Some(StoreError::OsWrapFailed));
        assert_eq!(s.wrap_kinds(), vec!["passphrase".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn store_file_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("v".into()), BTreeMap::new())
            .unwrap();
        for f in [path.clone(), sibling(&path, "prev")] {
            assert_eq!(fs::metadata(f).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[cfg(windows)]
    #[test]
    fn store_file_acl_names_only_the_current_user() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.secretant");
        let mut s = new_store(&dir);
        s.put("A", SecretValue::from_string("v".into()), BTreeMap::new())
            .unwrap();
        let out = std::process::Command::new("icacls")
            .arg(&path)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        let user = std::env::var("USERNAME").unwrap().to_lowercase();
        let entries: Vec<&str> = text.lines().filter(|l| l.contains(":(")).collect();
        assert!(!entries.is_empty(), "probe sees ACL entries");
        for e in &entries {
            assert!(e.contains(&user), "an ACL entry names someone else: {text}");
        }
        for wide in [
            "everyone",
            "builtin\\users",
            "authenticated users",
            "nt authority\\system",
            "administrators",
        ] {
            assert!(!text.contains(wide), "ACL mentions {wide}");
        }
    }
}
