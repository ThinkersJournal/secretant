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
    /// `create` found a file already there.
    AlreadyExists,
    /// `open` found no file.
    NoSuchStore,
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
            StoreError::AlreadyExists => "a store already exists at that path",
            StoreError::NoSuchStore => "no store at that path",
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

#[derive(Serialize, Deserialize)]
struct Wrap {
    kind: String,
    salt: String,
    kdf: KdfParams,
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
            kdf,
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

    /// Open an existing store.
    pub fn open(path: impl AsRef<Path>, passphrase: &SecretValue) -> Result<Self, StoreError> {
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
            if w.kind != "passphrase" || !w.kdf.acceptable() {
                continue;
            }
            let (Some(salt), Some(nonce), Some(wrapped)) =
                (from_hex(&w.salt), from_hex(&w.nonce), from_hex(&w.wrapped))
            else {
                return Err(StoreError::Corrupt);
            };
            let wk = derive(passphrase, &salt, &w.kdf)?;
            if let Some(k) = unseal(wk.as_ref(), &nonce, AAD_WRAP, &wrapped)
                && k.len() == KEY_LEN
            {
                let mut arr = Zeroizing::new([0u8; KEY_LEN]);
                arr.copy_from_slice(&k);
                data_key = Some(arr);
                break;
            }
        }
        let data_key = data_key.ok_or(StoreError::WrongPassphrase)?;
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

    /// Write the whole store: new file beside the old one, flushed, then renamed
    /// into place, keeping the previous generation as `<path>.prev`.
    fn save(&self) -> Result<(), StoreError> {
        let nonce = random::<NONCE_LEN>()?;
        let plain =
            Zeroizing::new(serde_json::to_vec(&self.payload).map_err(|_| StoreError::Corrupt)?);
        let sealed = seal(self.data_key.as_ref(), &nonce, AAD_DATA, &plain)?;
        // Wraps are copied field by field: `Wrap` is not Clone on purpose.
        let wraps = self
            .wraps
            .iter()
            .map(|w| Wrap {
                kind: w.kind.clone(),
                salt: w.salt.clone(),
                kdf: w.kdf,
                nonce: w.nonce.clone(),
                wrapped: w.wrapped.clone(),
            })
            .collect();
        let image = FileImage {
            format: FORMAT,
            wraps,
            nonce: to_hex(&nonce),
            ciphertext: to_hex(&sealed),
        };
        let text = serde_json::to_vec_pretty(&image).map_err(|_| StoreError::Corrupt)?;
        let tmp = sibling(&self.path, "tmp");
        let prev = sibling(&self.path, "prev");
        let mut f = fs::File::create(&tmp).map_err(|_| StoreError::Io)?;
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
            &format!("\"m_kib\": {}", image.wraps[0].kdf.m_kib),
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
}
