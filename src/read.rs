// SPDX-License-Identifier: MIT OR Apache-2.0
//! The read API for adapters (ConfigurAnt's `SecretSource` and similar).
//!
//! `SecretReader::open(config)` then `get(name)`. Four error classes, matching
//! the classes a `SecretSource` must report: [`ReadError::NotFound`],
//! [`ReadError::Denied`], [`ReadError::Unreachable`], [`ReadError::TimedOut`].
//! An error carries its class and nothing else: no store text, no name, no path.
//!
//! No cache: every `get` opens the store file afresh, reads, and drops the
//! opened store, so a rotated value is seen on the next call and nothing is
//! kept between calls except the config (including the unlock secret the caller
//! gave). Every call is bounded by `config.timeout`.
//!
//! Limit, stated once: any process running as the same user can do what this
//! API does (the OS-bound wrap and a readable store file are the same-user
//! boundary). SecretAnt does not defend against a hostile process of the owner.

use crate::store::{FileStore, Store, StoreError, Unlock};
use crate::value::SecretValue;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

/// How to unlock, owning its secret.
pub enum ReadUnlock {
    /// The passphrase.
    Passphrase(SecretValue),
    /// The recovery key text.
    Recovery(SecretValue),
    /// The OS-bound wrap (same user, same machine).
    Os,
}

/// Where the store is, how to open it, and how long to wait.
pub struct ReadConfig {
    /// The store file.
    pub path: PathBuf,
    /// How to open it.
    pub unlock: ReadUnlock,
    /// Longest any single `open` or `get` may take.
    pub timeout: Duration,
}

impl fmt::Debug for ReadConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReadConfig(<redacted>)")
    }
}

/// Why a read failed. Class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The store has no such entry.
    NotFound,
    /// The unlock was refused: wrong passphrase, recovery key or OS user.
    Denied,
    /// The store could not be reached or read: missing, unreadable, damaged,
    /// or an unsupported format.
    Unreachable,
    /// The call took longer than the configured timeout.
    TimedOut,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadError::NotFound => "not found",
            ReadError::Denied => "access denied",
            ReadError::Unreachable => "store unreachable",
            ReadError::TimedOut => "timed out",
        })
    }
}

impl std::error::Error for ReadError {}

impl From<StoreError> for ReadError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound | StoreError::BadName => ReadError::NotFound,
            StoreError::WrongPassphrase
            | StoreError::WrongRecoveryKey
            | StoreError::OsWrapFailed => ReadError::Denied,
            StoreError::Corrupt
            | StoreError::UnsupportedFormat
            | StoreError::AlreadyExists
            | StoreError::Conflict
            | StoreError::NoSuchStore
            | StoreError::Io => ReadError::Unreachable,
        }
    }
}

/// A handle for reading secrets by name.
pub struct SecretReader {
    config: Arc<ReadConfig>,
}

impl fmt::Debug for SecretReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretReader(<redacted>)")
    }
}

fn open_store(config: &ReadConfig) -> Result<FileStore, StoreError> {
    match &config.unlock {
        ReadUnlock::Passphrase(p) => FileStore::open_with(&config.path, Unlock::Passphrase(p)),
        ReadUnlock::Recovery(k) => FileStore::open_with(&config.path, Unlock::Recovery(k)),
        ReadUnlock::Os => FileStore::open_with(&config.path, Unlock::Os),
    }
}

impl SecretReader {
    /// Check that the store opens with this config, within the timeout, and keep
    /// the config for later `get` calls. The opened store is not kept.
    pub fn open(config: ReadConfig) -> Result<Self, ReadError> {
        let reader = Self {
            config: Arc::new(config),
        };
        reader.bounded(|c| open_store(c).map(|_| ()))?;
        Ok(reader)
    }

    /// The latest value of `name`, read fresh from the file.
    pub fn get(&self, name: &str) -> Result<SecretValue, ReadError> {
        let name = name.to_owned();
        self.bounded(move |c| open_store(c)?.get(&name))
    }

    /// Run `job` on a worker thread and wait at most the timeout. A job that
    /// outlives the timeout is abandoned (it cannot be cancelled) and its result
    /// dropped when it finishes, which wipes any value it held.
    fn bounded<T, F>(&self, job: F) -> Result<T, ReadError>
    where
        T: Send + 'static,
        F: FnOnce(&ReadConfig) -> Result<T, StoreError> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let config = Arc::clone(&self.config);
        let timeout = config.timeout;
        thread::spawn(move || {
            let _ = tx.send(job(&config));
        });
        match rx.recv_timeout(timeout) {
            Ok(result) => result.map_err(ReadError::from),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(ReadError::TimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ReadError::Unreachable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::KdfParams;
    use std::collections::BTreeMap;

    const CANARY: &str = "hunter2-canary-read";
    const FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };

    fn pass(s: &str) -> SecretValue {
        SecretValue::from_string(s.to_string())
    }

    fn make(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("s.secretant");
        let mut s = FileStore::create_with_params(&path, &pass("pw"), FAST).unwrap();
        s.put(
            CANARY,
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
        path
    }

    fn cfg(path: PathBuf, unlock: ReadUnlock, ms: u64) -> ReadConfig {
        ReadConfig {
            path,
            unlock,
            timeout: Duration::from_millis(ms),
        }
    }

    #[test]
    fn get_returns_the_value_and_not_found_is_its_own_class() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(&dir);
        let r = SecretReader::open(cfg(path, ReadUnlock::Passphrase(pass("pw")), 10_000)).unwrap();
        assert!(r.get(CANARY).unwrap().expose() == CANARY.as_bytes());
        assert_eq!(r.get("missing").err(), Some(ReadError::NotFound));
        assert_eq!(r.get("").err(), Some(ReadError::NotFound));
    }

    #[test]
    fn wrong_unlock_is_denied_and_missing_or_damaged_store_is_unreachable() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(&dir);
        let denied = [
            ReadUnlock::Passphrase(pass("nope")),
            ReadUnlock::Recovery(pass("nope")),
            ReadUnlock::Os,
        ];
        for u in denied {
            assert_eq!(
                SecretReader::open(cfg(path.clone(), u, 10_000)).err(),
                Some(ReadError::Denied)
            );
        }
        let gone = dir.path().join("none");
        assert_eq!(
            SecretReader::open(cfg(gone, ReadUnlock::Os, 10_000)).err(),
            Some(ReadError::Unreachable)
        );
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(
            SecretReader::open(cfg(path, ReadUnlock::Os, 10_000)).err(),
            Some(ReadError::Unreachable)
        );
    }

    #[test]
    fn a_slow_open_times_out_within_the_bound() {
        // Real Argon2 cost (64 MiB, 3 passes) against a 1 ms bound: the control
        // below shows the same store opens with a generous bound.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slow.secretant");
        FileStore::create(&path, &pass("pw")).unwrap();
        let start = std::time::Instant::now();
        let r = SecretReader::open(cfg(path.clone(), ReadUnlock::Passphrase(pass("pw")), 1));
        assert_eq!(r.err(), Some(ReadError::TimedOut));
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(SecretReader::open(cfg(path, ReadUnlock::Passphrase(pass("pw")), 60_000)).is_ok());
    }

    #[test]
    fn no_cache_a_rotated_value_is_seen_on_the_next_get() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(&dir);
        let r = SecretReader::open(cfg(
            path.clone(),
            ReadUnlock::Passphrase(pass("pw")),
            10_000,
        ))
        .unwrap();
        assert!(r.get(CANARY).unwrap().expose() == CANARY.as_bytes());
        let mut s = FileStore::open(&path, &pass("pw")).unwrap();
        s.put(CANARY, pass("rotated"), BTreeMap::new()).unwrap();
        assert!(r.get(CANARY).unwrap().expose() == b"rotated");
        // And no extra file is left beside the store by reading.
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().all(|n| n.starts_with("s.secretant")));
    }

    #[test]
    fn errors_and_handles_carry_no_store_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(&dir);
        let r = SecretReader::open(cfg(
            path.clone(),
            ReadUnlock::Passphrase(pass("pw")),
            10_000,
        ))
        .unwrap();
        let e = r.get(&format!("{CANARY}-missing")).err().unwrap();
        let shown = format!("{e:?} {e} {r:?}");
        assert!(!shown.contains(CANARY));
        assert!(!shown.contains(path.to_string_lossy().as_ref()));
        let c = cfg(path, ReadUnlock::Passphrase(pass(CANARY)), 1);
        assert!(!format!("{c:?}").contains(CANARY));
    }
}
