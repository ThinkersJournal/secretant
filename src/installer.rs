// SPDX-License-Identifier: MIT OR Apache-2.0
//! The installer's Store step (ROADMAP row 8; design in `docs/INSTALLER-STEPS.md`).
//!
//! `probe`, `plan`, `apply`, `read_back`, as the Humboldt installer's own drivers
//! do. The library never asks, prints or logs: the installer shows the recovery
//! key and takes the typed-back confirmation. Everything here carries paths,
//! counts and error classes, never a value.
//!
//! Creating a store is ordered so that a crash never leaves a store whose
//! recovery key nobody saw: the store is written at `PATH.pending`, the key is
//! returned once, and the file only becomes `PATH` after [`confirm_recovery`]
//! has opened it with the key the person typed back.

use crate::store::{FileStore, Inspection, StoreError, Unlock};
use crate::value::SecretValue;
use std::fmt;
use std::path::{Path, PathBuf};

/// Why a step could not go on. A class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// A store is already there and the plan was to create one.
    Exists,
    /// The situation changed between `plan` and `apply`: plan again.
    StalePlan,
    /// An OS-bound wrap was asked for on a platform that has none.
    OsWrapUnavailable,
    /// The typed-back recovery key did not open the pending store.
    RecoveryNotConfirmed,
    /// The unlock did not open the store.
    WrongUnlock,
    /// An empty passphrase protects nothing.
    EmptyPassphrase,
    /// A file of ours is damaged or is not a store of a format this version reads.
    Damaged,
    /// A file operation failed.
    Io,
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InstallError::Exists => "a store already exists there",
            InstallError::StalePlan => "the situation changed since the plan was made: plan again",
            InstallError::OsWrapUnavailable => {
                "this system has no operating-system-bound wrap: use a passphrase and a recovery key"
            }
            InstallError::RecoveryNotConfirmed => {
                "the recovery key typed back did not open the new store; nothing was finished"
            }
            InstallError::WrongUnlock => "the passphrase or key did not open the store",
            InstallError::EmptyPassphrase => "an empty passphrase is not allowed",
            InstallError::Damaged => "the store file is damaged or not a store this version reads",
            InstallError::Io => "a file operation failed",
        })
    }
}

impl std::error::Error for InstallError {}

impl From<StoreError> for InstallError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::AlreadyExists => InstallError::Exists,
            StoreError::WrongPassphrase
            | StoreError::WrongRecoveryKey
            | StoreError::OsWrapFailed => InstallError::WrongUnlock,
            StoreError::EmptyPassphrase => InstallError::EmptyPassphrase,
            StoreError::Io => InstallError::Io,
            _ => InstallError::Damaged,
        }
    }
}

/// The path a new store waits at until its recovery key is confirmed.
pub fn pending_path(path: &Path) -> PathBuf {
    sibling(path, ".pending")
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// What is at the store path right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreProbe {
    /// Nothing there.
    Absent,
    /// A store file: its plain header (format and wraps), read without unlocking.
    Present(Inspection),
    /// An earlier run created a store but never finished (no confirmed key).
    Pending,
    /// A file is there that cannot be read as a store.
    Unreadable(InstallError),
}

/// Look at `path`. Reads only the plain header; needs no unlock.
pub fn probe_store(path: &Path) -> StoreProbe {
    match FileStore::inspect(path) {
        Ok(h) => StoreProbe::Present(h),
        Err(StoreError::NoSuchStore) => {
            if pending_path(path).exists() {
                StoreProbe::Pending
            } else {
                StoreProbe::Absent
            }
        }
        Err(e) => StoreProbe::Unreadable(e.into()),
    }
}

/// What the step will do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreAction {
    /// Create a store: passphrase wrap, recovery wrap, and an OS-bound wrap if asked.
    Create {
        /// Also add the OS-bound wrap (Windows).
        os_wrap: bool,
    },
    /// Throw away an unfinished earlier run's file (it holds none of our
    /// secrets: they are added after confirmation), then create.
    DiscardPendingAndCreate {
        /// Also add the OS-bound wrap (Windows).
        os_wrap: bool,
    },
    /// The person's store is there: use it, write nothing, never create a second.
    UseExisting,
    /// Stop: the class says why.
    Refuse(InstallError),
}

/// A plan: what to do, and the probe it was made from, so `apply` can refuse
/// to act on a situation that has changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePlan {
    path: PathBuf,
    probe: StoreProbe,
    /// What the step will do.
    pub action: StoreAction,
}

impl StorePlan {
    /// The store path this plan is for.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Turn a probe into a plan. Pure: writes nothing. `os_wrap` asks for the
/// OS-bound wrap; where the platform has none the plan refuses (nothing
/// falls back silently).
pub fn plan_store(path: &Path, probe: StoreProbe, os_wrap: bool) -> StorePlan {
    let action = if os_wrap && !cfg!(windows) {
        StoreAction::Refuse(InstallError::OsWrapUnavailable)
    } else {
        match &probe {
            StoreProbe::Absent => StoreAction::Create { os_wrap },
            StoreProbe::Pending => StoreAction::DiscardPendingAndCreate { os_wrap },
            StoreProbe::Present(_) => StoreAction::UseExisting,
            StoreProbe::Unreadable(e) => StoreAction::Refuse(*e),
        }
    };
    StorePlan {
        path: path.to_path_buf(),
        probe,
        action,
    }
}

/// A store that exists only as `PATH.pending`, until its key is confirmed.
#[derive(Debug)]
pub struct PendingStore {
    path: PathBuf,
}

/// The result of `apply`.
#[derive(Debug)]
pub enum StoreApplied {
    /// Nothing was written (the person's store is used as it is).
    Unchanged,
    /// A pending store was written. Show `recovery_key` to the person once,
    /// take the key typed back, and call [`confirm_recovery`]. The library
    /// keeps no copy of the key.
    Pending {
        /// The pending store.
        store: PendingStore,
        /// The recovery key, to be shown once.
        recovery_key: SecretValue,
    },
}

/// Do exactly the plan, if the situation is still the one it was made from.
/// `passphrase` is the new store's passphrase (ignored for `UseExisting`).
pub fn apply_store(
    plan: &StorePlan,
    passphrase: &SecretValue,
) -> Result<StoreApplied, InstallError> {
    if probe_store(&plan.path) != plan.probe {
        return Err(InstallError::StalePlan);
    }
    let os_wrap = match plan.action {
        StoreAction::Refuse(e) => return Err(e),
        StoreAction::UseExisting => return Ok(StoreApplied::Unchanged),
        StoreAction::Create { os_wrap } => os_wrap,
        StoreAction::DiscardPendingAndCreate { os_wrap } => {
            discard_pending(&plan.path)?;
            os_wrap
        }
    };
    if passphrase.is_empty() {
        return Err(InstallError::EmptyPassphrase);
    }
    let pending = pending_path(&plan.path);
    let made = (|| -> Result<SecretValue, InstallError> {
        let mut s = FileStore::create(&pending, passphrase)?;
        if os_wrap {
            s.add_os_wrap()?;
        }
        Ok(s.add_recovery_wrap()?)
    })();
    match made {
        Ok(recovery_key) => Ok(StoreApplied::Pending {
            store: PendingStore {
                path: plan.path.clone(),
            },
            recovery_key,
        }),
        Err(e) => {
            // A half-made pending file is removed so the next run starts clean.
            let _ = discard_pending(&plan.path);
            Err(e)
        }
    }
}

/// Remove an unfinished run's files (`PATH.pending` and its `.prev`). A store
/// at `PATH` is never touched.
pub fn discard_pending(path: &Path) -> Result<(), InstallError> {
    let pending = pending_path(path);
    for p in [sibling(&pending, ".prev"), pending] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(InstallError::Io),
        }
    }
    Ok(())
}

/// The person typed the recovery key back: if it opens the pending store, the
/// file becomes the store at `PATH`. If not, the pending file stays where it is
/// and `PATH` stays absent.
pub fn confirm_recovery(pending: &PendingStore, typed: &SecretValue) -> Result<(), InstallError> {
    let from = pending_path(&pending.path);
    FileStore::open_with(&from, Unlock::Recovery(typed))
        .map_err(|_| InstallError::RecoveryNotConfirmed)?;
    if pending.path.exists() {
        return Err(InstallError::Exists);
    }
    std::fs::rename(&from, &pending.path).map_err(|_| InstallError::Io)?;
    // The `.prev` generation of the pending file is not part of the store.
    let _ = std::fs::remove_file(sibling(&from, ".prev"));
    Ok(())
}

/// What `read_back` found. Counts and kinds only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreReport {
    /// The wrap kinds the file has.
    pub wraps: Vec<String>,
    /// How many entries it holds.
    pub entries: u32,
}

/// Prove the store opens with `unlock`, and say what it has.
pub fn read_back_store(path: &Path, unlock: Unlock<'_>) -> Result<StoreReport, InstallError> {
    use crate::store::Store;
    let s = FileStore::open_with(path, unlock)?;
    Ok(StoreReport {
        wraps: s.wrap_kinds(),
        entries: u32::try_from(s.list().len()).unwrap_or(u32::MAX),
    })
}
