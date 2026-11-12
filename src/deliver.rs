// SPDX-License-Identifier: MIT OR Apache-2.0
//! Delivery (ROADMAP row 5): place a stored secret where a program reads it,
//! check that it is still there, and say what drifted, never showing a value.
//!
//! Two targets: [`Target::File`] (the value, exactly, in one owner-only file)
//! and [`Target::EnvFile`] (one `VAR=value` line in an owner-only environment
//! file; other lines are kept). Both are derived copies: the store stays the
//! one source of truth.
//!
//! - [`plan`] reads and writes nothing; [`apply`] writes each target
//!   atomically (a private temporary file, then a rename), so a target that
//!   fails keeps its old content and stays [`State::Stale`]: never half-rotated.
//! - [`verify`] reports one [`State`] per placement. A report holds the
//!   placement's index and a state, nothing from the value.
//! - The [`Ledger`] records which version of which name was put where. It holds
//!   names, paths and version numbers only, never values.

use crate::store::{Store, StoreError, is_private, write_private_atomic};
use crate::value::SecretValue;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Where a value is placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// The file holds the value and nothing else.
    File(PathBuf),
    /// The file holds `var=value` lines; this placement owns the line for `var`.
    EnvFile {
        /// The environment file.
        path: PathBuf,
        /// The variable name (`[A-Za-z_][A-Za-z0-9_]*`).
        var: String,
    },
}

impl Target {
    fn path(&self) -> &Path {
        match self {
            Target::File(p) | Target::EnvFile { path: p, .. } => p,
        }
    }

    fn key(&self) -> String {
        match self {
            Target::File(p) => format!("file:{}", p.display()),
            Target::EnvFile { path, var } => format!("env:{}#{var}", path.display()),
        }
    }
}

/// One secret to place at one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The store name.
    pub name: String,
    /// Where it goes.
    pub target: Target,
}

/// Why a delivery step failed. A class only: no name, path or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverError {
    /// The store refused (missing name, and so on).
    Store(StoreError),
    /// The target could not be read or written; it was left as it was.
    Io,
    /// The value cannot be written to that kind of target (a line break or a
    /// byte that is not text in an environment file, or a bad variable name).
    Unsupported,
}

impl From<StoreError> for DeliverError {
    fn from(e: StoreError) -> Self {
        DeliverError::Store(e)
    }
}

impl std::fmt::Display for DeliverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliverError::Store(e) => e.fmt(f),
            DeliverError::Io => f.write_str("a target could not be read or written"),
            DeliverError::Unsupported => f.write_str("the value does not fit that kind of target"),
        }
    }
}

impl std::error::Error for DeliverError {}

/// What a placement's target holds, compared with the store's latest version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Holds the latest value, and the file is owner-only.
    InSync,
    /// Holds an older version this ledger placed; a new value is waiting.
    Stale,
    /// Holds a value that is no version the ledger placed: edited by hand.
    Drifted,
    /// Nothing there (no file, or no line for the variable).
    Missing,
    /// Holds the latest value but other users can read the file.
    LoosePerms,
    /// The store or the target could not be read.
    Unreadable,
}

/// One line of a plan: what `apply` would do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The target is absent; `apply` creates it.
    Create,
    /// The target differs or is loose; `apply` rewrites it.
    Update,
    /// Nothing to do.
    Unchanged,
}

/// The result of one placement in [`apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Index into the placements given.
    pub index: usize,
    /// The version placed, or why not.
    pub result: Result<u32, DeliverError>,
}

#[derive(Serialize, Deserialize, Default)]
struct LedgerFile {
    placed: Vec<Record>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Record {
    name: String,
    target: String,
    version: u32,
}

/// Which version of which name was placed where. Names, paths and numbers only.
pub struct Ledger {
    path: PathBuf,
    file: LedgerFile,
}

impl Ledger {
    /// Open the ledger at `path`; a missing file is an empty ledger.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DeliverError> {
        let path = path.as_ref().to_path_buf();
        let file = match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|_| DeliverError::Io)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => LedgerFile::default(),
            Err(_) => return Err(DeliverError::Io),
        };
        Ok(Ledger { path, file })
    }

    fn version(&self, p: &Placement) -> Option<u32> {
        let key = p.target.key();
        self.file
            .placed
            .iter()
            .find(|r| r.name == p.name && r.target == key)
            .map(|r| r.version)
    }

    fn record(&mut self, p: &Placement, version: u32) -> Result<(), DeliverError> {
        let key = p.target.key();
        match self
            .file
            .placed
            .iter_mut()
            .find(|r| r.name == p.name && r.target == key)
        {
            Some(r) => r.version = version,
            None => self.file.placed.push(Record {
                name: p.name.clone(),
                target: key,
                version,
            }),
        }
        let text = serde_json::to_vec_pretty(&self.file).map_err(|_| DeliverError::Io)?;
        write_private_atomic(&self.path, &text).map_err(|_| DeliverError::Io)
    }
}

fn valid_var(var: &str) -> bool {
    !var.is_empty()
        && !var.starts_with(|c: char| c.is_ascii_digit())
        && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A value fit for one `VAR=value` line.
fn line_safe(v: &[u8]) -> bool {
    std::str::from_utf8(v).is_ok() && !v.iter().any(|b| matches!(b, b'\n' | b'\r' | 0))
}

/// What the target holds for this placement, if anything.
fn current(p: &Placement) -> Result<Option<Zeroizing<Vec<u8>>>, DeliverError> {
    let bytes = match fs::read(p.target.path()) {
        Ok(b) => Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DeliverError::Io),
    };
    match &p.target {
        Target::File(_) => Ok(Some(bytes)),
        Target::EnvFile { var, .. } => {
            let prefix = format!("{var}=");
            for line in bytes.split(|b| *b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if let Some(v) = line.strip_prefix(prefix.as_bytes()) {
                    return Ok(Some(Zeroizing::new(v.to_vec())));
                }
            }
            Ok(None)
        }
    }
}

/// The whole new content of the target, with `value` placed.
fn render(p: &Placement, value: &SecretValue) -> Result<Zeroizing<Vec<u8>>, DeliverError> {
    match &p.target {
        Target::File(_) => Ok(Zeroizing::new(value.expose().to_vec())),
        Target::EnvFile { path, var } => {
            if !valid_var(var) || !line_safe(value.expose()) {
                return Err(DeliverError::Unsupported);
            }
            let old = match fs::read(path) {
                Ok(b) => Zeroizing::new(b),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Zeroizing::new(Vec::new()),
                Err(_) => return Err(DeliverError::Io),
            };
            let prefix = format!("{var}=");
            let mut out = Zeroizing::new(Vec::new());
            let mut replaced = false;
            let mut lines: Vec<&[u8]> = old.split(|b| *b == b'\n').collect();
            if lines.last() == Some(&&b""[..]) {
                lines.pop();
            }
            for line in lines {
                let bare = line.strip_suffix(b"\r").unwrap_or(line);
                if bare.starts_with(prefix.as_bytes()) {
                    if !replaced {
                        out.extend_from_slice(prefix.as_bytes());
                        out.extend_from_slice(value.expose());
                        out.push(b'\n');
                        replaced = true;
                    }
                } else {
                    out.extend_from_slice(line);
                    out.push(b'\n');
                }
            }
            if !replaced {
                out.extend_from_slice(prefix.as_bytes());
                out.extend_from_slice(value.expose());
                out.push(b'\n');
            }
            Ok(out)
        }
    }
}

fn state_of(store: &dyn Store, ledger: &Ledger, p: &Placement) -> State {
    let Ok(info) = store.describe(&p.name) else {
        return State::Unreadable;
    };
    let Ok(latest) = store.get(&p.name) else {
        return State::Unreadable;
    };
    let held = match current(p) {
        Ok(Some(v)) => v,
        Ok(None) => return State::Missing,
        Err(_) => return State::Unreadable,
    };
    if held.as_slice() == latest.expose() {
        return if is_private(p.target.path()) {
            State::InSync
        } else {
            State::LoosePerms
        };
    }
    // Different from the latest: an older version we placed, or a hand edit.
    if let Some(v) = ledger.version(p)
        && v < info.latest
        && let Ok(old) = store.get_version(&p.name, v)
        && held.as_slice() == old.expose()
    {
        return State::Stale;
    }
    State::Drifted
}

/// What `apply` would do for each placement. Reads the store and the targets;
/// writes nothing.
pub fn plan(store: &dyn Store, ledger: &Ledger, placements: &[Placement]) -> Vec<(usize, Action)> {
    placements
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let a = match state_of(store, ledger, p) {
                State::InSync => Action::Unchanged,
                State::Missing => Action::Create,
                _ => Action::Update,
            };
            (i, a)
        })
        .collect()
}

/// Place the latest value of each name at its target. Each target is written
/// atomically and the ledger is updated only after it succeeds, so a failure
/// leaves that target as it was (stale, never half-rotated) and the others
/// proceed.
pub fn apply(store: &dyn Store, ledger: &mut Ledger, placements: &[Placement]) -> Vec<Outcome> {
    placements
        .iter()
        .enumerate()
        .map(|(index, p)| {
            let result = (|| {
                let info = store.describe(&p.name)?;
                let value = store.get(&p.name)?;
                let content = render(p, &value)?;
                write_private_atomic(p.target.path(), &content).map_err(|_| DeliverError::Io)?;
                ledger.record(p, info.latest)?;
                Ok(info.latest)
            })();
            Outcome { index, result }
        })
        .collect()
}

/// One state per placement, in order. Never carries a value.
pub fn verify(store: &dyn Store, ledger: &Ledger, placements: &[Placement]) -> Vec<(usize, State)> {
    placements
        .iter()
        .enumerate()
        .map(|(i, p)| (i, state_of(store, ledger, p)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{FileStore, KdfParams};
    use std::collections::BTreeMap;

    const FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };
    const V1: &str = "CANARY-deliver-v1-4d8e21";
    const V2: &str = "CANARY-deliver-v2-b07c93";
    const NAME: &str = "db_url";

    struct Rig {
        dir: tempfile::TempDir,
        store: FileStore,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let pw = SecretValue::from_string("pw".into());
        let mut store =
            FileStore::create_with_params(dir.path().join("s.secretant"), &pw, FAST).unwrap();
        store
            .put(NAME, SecretValue::from_string(V1.into()), BTreeMap::new())
            .unwrap();
        Rig { dir, store }
    }

    impl Rig {
        fn ledger(&self) -> Ledger {
            Ledger::open(self.dir.path().join("ledger.json")).unwrap()
        }
        fn file(&self) -> Placement {
            Placement {
                name: NAME.into(),
                target: Target::File(self.dir.path().join("out.secret")),
            }
        }
        fn env(&self) -> Placement {
            Placement {
                name: NAME.into(),
                target: Target::EnvFile {
                    path: self.dir.path().join("app.env"),
                    var: "DATABASE_URL".into(),
                },
            }
        }
        fn rotate(&mut self, v: &str) {
            self.store
                .put(NAME, SecretValue::from_string(v.into()), BTreeMap::new())
                .unwrap();
        }
    }

    #[test]
    fn plan_then_apply_then_in_sync() {
        let r = rig();
        let ps = [r.file(), r.env()];
        let mut l = r.ledger();
        assert_eq!(
            plan(&r.store, &l, &ps),
            vec![(0, Action::Create), (1, Action::Create)]
        );
        // plan wrote nothing
        assert!(!r.dir.path().join("out.secret").exists());
        let out = apply(&r.store, &mut l, &ps);
        assert!(out.iter().all(|o| o.result == Ok(1)));
        assert_eq!(
            verify(&r.store, &l, &ps),
            vec![(0, State::InSync), (1, State::InSync)]
        );
        assert_eq!(
            fs::read(r.dir.path().join("out.secret")).unwrap(),
            V1.as_bytes()
        );
        assert_eq!(
            fs::read_to_string(r.dir.path().join("app.env")).unwrap(),
            format!("DATABASE_URL={V1}\n")
        );
        assert_eq!(plan(&r.store, &l, &ps)[0].1, Action::Unchanged);
    }

    #[test]
    fn delivered_files_are_owner_only_and_loosening_is_reported() {
        let r = rig();
        let ps = [r.file()];
        let mut l = r.ledger();
        apply(&r.store, &mut l, &ps);
        let path = r.dir.path().join("out.secret");
        assert!(is_private(&path), "a delivered file must be owner-only");
        // loosen it by hand
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        #[cfg(windows)]
        {
            let ok = std::process::Command::new("icacls")
                .arg(&path)
                .args(["/grant", "*S-1-1-0:R"])
                .output()
                .unwrap()
                .status
                .success();
            assert!(ok);
        }
        assert_eq!(verify(&r.store, &l, &ps), vec![(0, State::LoosePerms)]);
        // apply repairs it
        apply(&r.store, &mut l, &ps);
        assert_eq!(verify(&r.store, &l, &ps), vec![(0, State::InSync)]);
    }

    #[test]
    fn rotation_makes_targets_stale_then_apply_updates() {
        let mut r = rig();
        let ps = [r.file(), r.env()];
        let mut l = r.ledger();
        apply(&r.store, &mut l, &ps);
        r.rotate(V2);
        assert_eq!(
            verify(&r.store, &l, &ps),
            vec![(0, State::Stale), (1, State::Stale)]
        );
        assert_eq!(plan(&r.store, &l, &ps)[0].1, Action::Update);
        let out = apply(&r.store, &mut l, &ps);
        assert!(out.iter().all(|o| o.result == Ok(2)));
        assert_eq!(
            verify(&r.store, &l, &ps),
            vec![(0, State::InSync), (1, State::InSync)]
        );
    }

    #[test]
    fn a_hand_edit_is_drift_and_the_report_has_no_value() {
        let r = rig();
        let ps = [r.file(), r.env()];
        let mut l = r.ledger();
        apply(&r.store, &mut l, &ps);
        fs::write(r.dir.path().join("out.secret"), b"edited by hand").unwrap();
        fs::write(r.dir.path().join("app.env"), b"DATABASE_URL=other\n").unwrap();
        let rep = verify(&r.store, &l, &ps);
        assert_eq!(rep, vec![(0, State::Drifted), (1, State::Drifted)]);
        let shown = format!("{rep:?} {:?}", plan(&r.store, &l, &ps));
        assert!(
            !shown.contains(V1) && !shown.contains("edited by hand") && !shown.contains("other")
        );
        // a deleted file and a deleted line are Missing
        fs::remove_file(r.dir.path().join("out.secret")).unwrap();
        fs::write(r.dir.path().join("app.env"), b"OTHER=1\n").unwrap();
        assert_eq!(
            verify(&r.store, &l, &ps),
            vec![(0, State::Missing), (1, State::Missing)]
        );
    }

    #[test]
    fn a_failed_target_stays_stale_and_the_rest_proceed() {
        let mut r = rig();
        let ps = [r.file(), r.env()];
        let mut l = r.ledger();
        apply(&r.store, &mut l, &ps);
        r.rotate(V2);
        // Block the first target's temporary file with a directory.
        let block = r.dir.path().join("out.secret.tmp");
        fs::create_dir(&block).unwrap();
        let out = apply(&r.store, &mut l, &ps);
        assert_eq!(out[0].result, Err(DeliverError::Io));
        assert_eq!(out[1].result, Ok(2));
        // The failed target holds the OLD value whole: never half-rotated.
        assert_eq!(
            fs::read(r.dir.path().join("out.secret")).unwrap(),
            V1.as_bytes()
        );
        assert_eq!(
            verify(&r.store, &l, &ps),
            vec![(0, State::Stale), (1, State::InSync)]
        );
        // The error text names no path or value.
        let text = out[0].result.unwrap_err().to_string();
        assert!(!text.contains("out.secret") && !text.contains(V1));
        // Clear the block; the next apply completes it.
        fs::remove_dir(&block).unwrap();
        apply(&r.store, &mut l, &ps);
        assert_eq!(verify(&r.store, &l, &ps)[0].1, State::InSync);
    }

    #[test]
    fn env_file_keeps_other_lines_and_refuses_unsafe_values() {
        let mut r = rig();
        let ps = [r.env()];
        let path = r.dir.path().join("app.env");
        fs::write(&path, "A=1\nDATABASE_URL=old\nB=2\n").unwrap();
        let mut l = r.ledger();
        apply(&r.store, &mut l, &ps);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!("A=1\nDATABASE_URL={V1}\nB=2\n")
        );
        // a value with a line break cannot be one line
        r.store
            .put(
                NAME,
                SecretValue::from_string("a\nb".into()),
                BTreeMap::new(),
            )
            .unwrap();
        let out = apply(&r.store, &mut l, &ps);
        assert_eq!(out[0].result, Err(DeliverError::Unsupported));
        assert!(
            fs::read_to_string(&path).unwrap().contains(V1),
            "a refused write must change nothing"
        );
        // a bad variable name is refused
        let bad = Placement {
            name: NAME.into(),
            target: Target::EnvFile {
                path,
                var: "1 BAD".into(),
            },
        };
        assert_eq!(
            apply(&r.store, &mut l, &[bad])[0].result,
            Err(DeliverError::Unsupported)
        );
    }

    #[test]
    fn a_missing_name_is_a_store_error_and_the_ledger_holds_no_value() {
        let r = rig();
        let mut l = r.ledger();
        let p = Placement {
            name: "nope".into(),
            target: Target::File(r.dir.path().join("x")),
        };
        let out = apply(&r.store, &mut l, std::slice::from_ref(&p));
        assert_eq!(
            out[0].result,
            Err(DeliverError::Store(StoreError::NotFound))
        );
        assert_eq!(verify(&r.store, &l, &[p])[0].1, State::Unreadable);
        // the ledger after a real placement names the name, path and number, not the value
        let ps = [r.file()];
        apply(&r.store, &mut l, &ps);
        let ledger_text = fs::read_to_string(r.dir.path().join("ledger.json")).unwrap();
        assert!(ledger_text.contains(NAME) && !ledger_text.contains(V1));
    }
}
