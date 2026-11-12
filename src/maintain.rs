// SPDX-License-Identifier: MIT OR Apache-2.0
//! Keeping a store safe (ROADMAP row 7): backup, restore, and `doctor`.
//!
//! A backup is the store file as it is: ciphertext with no key in it, written
//! private to its owner. It is never trusted until [`check_backup`] has opened it
//! and read every entry. [`restore`] refuses to put a backup that does not open
//! in place of a store, and never replaces a store unless asked (keeping the
//! replaced file as `.prev`). [`doctor`] reads the file's plain header and
//! (if given an unlock) the whole store, and reports findings in fixed
//! sentences: no name, no value, no path.
//!
//! The export bundle and import are `FileStore::export_to`, `plan_import` and
//! `apply_import`: the bundle is a store file with its own passphrase wrap.

use crate::store::{
    FileStore, Inspection, Store, StoreError, Unlock, is_private, write_private_atomic,
};
use std::fs;
use std::path::{Path, PathBuf};

/// Copy the store at `store` to `dest` as it is (ciphertext). Refuses to
/// overwrite anything at `dest`. The copy is private to its owner.
pub fn backup(store: &Path, dest: &Path) -> Result<(), StoreError> {
    // The file must at least be a store of a readable format before it is copied.
    FileStore::inspect(store)?;
    if dest.exists() {
        return Err(StoreError::AlreadyExists);
    }
    let bytes = fs::read(store).map_err(|_| StoreError::Io)?;
    write_private_atomic(dest, &bytes)
}

/// What a backup holds, counted; no names, no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupSummary {
    /// How many entries.
    pub entries: u32,
    /// How many versions in all.
    pub versions: u32,
}

/// Open the backup at `path` with `unlock`, decrypt everything, and count. A
/// backup with a flipped byte fails here, loudly, with a named error.
pub fn check_backup(path: &Path, unlock: Unlock<'_>) -> Result<BackupSummary, StoreError> {
    let s = FileStore::open_with(path, unlock)?;
    let mut summary = BackupSummary {
        entries: 0,
        versions: 0,
    };
    for name in s.list() {
        let info = s.describe(&name)?;
        // Read every version: a value that does not decrypt is an error now,
        // not at the next emergency.
        for v in 1..=info.latest {
            s.get_version(&name, v)?;
        }
        summary.entries += 1;
        summary.versions += info.versions;
    }
    Ok(summary)
}

/// Put the backup at `backup_path` in place of the store at `store_path`.
/// The backup must pass [`check_backup`] first. If something is already at
/// `store_path`, `replace` must be true, and the old file is kept as `.prev`.
pub fn restore(
    backup_path: &Path,
    store_path: &Path,
    unlock: Unlock<'_>,
    replace: bool,
) -> Result<BackupSummary, StoreError> {
    let summary = check_backup(backup_path, unlock)?;
    if store_path.exists() {
        if !replace {
            return Err(StoreError::AlreadyExists);
        }
        let mut prev = store_path.as_os_str().to_owned();
        prev.push(".prev");
        let prev = PathBuf::from(prev);
        let _ = fs::remove_file(&prev);
        fs::rename(store_path, &prev).map_err(|_| StoreError::Io)?;
    }
    let bytes = fs::read(backup_path).map_err(|_| StoreError::Io)?;
    write_private_atomic(store_path, &bytes)?;
    Ok(summary)
}

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Worth knowing.
    Info,
    /// Fix soon.
    Warn,
    /// Broken: act now.
    Fail,
}

/// What `doctor` looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// The file is a store of a format this version reads.
    Readable,
    /// The file is readable by its owner only.
    OwnerOnly,
    /// How many ways of opening the store there are.
    Wraps,
    /// Whether a recovery wrap exists.
    Recovery,
    /// The passphrase wrap's key-derivation cost.
    KdfCost,
    /// The previous generation (`.prev`).
    PreviousGeneration,
    /// A leftover temporary file from an interrupted write.
    LeftoverTemp,
    /// The store opens with the unlock given and every entry decrypts.
    Opens,
}

/// One finding: what was checked, how it went, and what to do. The hint is a
/// fixed sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// What was checked.
    pub check: Check,
    /// How it went.
    pub level: Level,
    /// What it means and what to do about it.
    pub hint: &'static str,
}

fn f(check: Check, level: Level, hint: &'static str) -> Finding {
    Finding { check, level, hint }
}

/// The lowest Argon2id cost `doctor` calls acceptable: the OWASP floor for
/// Argon2id (19 MiB, 2 passes, 1 lane).
const KDF_FLOOR: (u32, u32) = (19 * 1024, 2);

/// Look the store over. `unlock` is optional: without it only the plain header,
/// the file permissions and the leftovers are checked.
pub fn doctor(path: &Path, unlock: Option<Unlock<'_>>) -> Vec<Finding> {
    let mut out = Vec::new();
    let header: Option<Inspection> = match FileStore::inspect(path) {
        Ok(h) => {
            out.push(f(
                Check::Readable,
                Level::Info,
                "the store file is readable",
            ));
            Some(h)
        }
        Err(StoreError::NoSuchStore) => {
            out.push(f(
                Check::Readable,
                Level::Fail,
                "no store at that path: check the path, or restore a backup",
            ));
            None
        }
        Err(StoreError::UnsupportedFormat) => {
            out.push(f(
                Check::Readable,
                Level::Fail,
                "the store has a format this version cannot read: use a newer secretant",
            ));
            None
        }
        Err(_) => {
            out.push(f(
                Check::Readable,
                Level::Fail,
                "the store file is damaged: restore the latest backup, or the .prev file",
            ));
            None
        }
    };
    let Some(h) = header else {
        return out;
    };

    if is_private(path) {
        out.push(f(
            Check::OwnerOnly,
            Level::Info,
            "the store file is private to its owner",
        ));
    } else {
        out.push(f(
            Check::OwnerOnly,
            Level::Fail,
            "other users can read the store file: restrict it to its owner",
        ));
    }

    match h.wraps.len() {
        0 => out.push(f(Check::Wraps, Level::Fail, "the store has no way to open it")),
        1 => out.push(f(
            Check::Wraps,
            Level::Warn,
            "only one way to open the store: add a recovery key or a second wrap before you need it",
        )),
        _ => out.push(f(Check::Wraps, Level::Info, "more than one way to open the store")),
    }
    if h.wraps.iter().any(|(k, _)| k == "recovery") {
        out.push(f(Check::Recovery, Level::Info, "a recovery wrap exists"));
    } else {
        out.push(f(
            Check::Recovery,
            Level::Warn,
            "no recovery key: if the passphrase is lost the store cannot be opened; add one and keep it apart from the store",
        ));
    }
    for (kind, kdf) in &h.wraps {
        if kind != "passphrase" {
            continue;
        }
        match kdf {
            Some(k) if k.m_kib >= KDF_FLOOR.0 && k.t >= KDF_FLOOR.1 => out.push(f(
                Check::KdfCost,
                Level::Info,
                "the passphrase wrap's key-derivation cost is at or above the recommended floor",
            )),
            _ => out.push(f(
                Check::KdfCost,
                Level::Warn,
                "the passphrase wrap's key-derivation cost is below the recommended floor: re-create the wrap with a higher cost",
            )),
        }
    }

    let sib = |ext: &str| {
        let mut s = path.as_os_str().to_owned();
        s.push(".");
        s.push(ext);
        PathBuf::from(s)
    };
    let prev = sib("prev");
    if prev.exists() {
        match FileStore::inspect(&prev) {
            Ok(_) => out.push(f(
                Check::PreviousGeneration,
                Level::Info,
                "a previous generation exists and is a store file",
            )),
            Err(_) => out.push(f(
                Check::PreviousGeneration,
                Level::Warn,
                "the previous generation is damaged: do not rely on it as a fallback",
            )),
        }
    } else {
        out.push(f(
            Check::PreviousGeneration,
            Level::Info,
            "no previous generation yet (it appears after the second write)",
        ));
    }
    if sib("tmp").exists() {
        out.push(f(
            Check::LeftoverTemp,
            Level::Warn,
            "a leftover temporary file from an interrupted write: the store is intact; remove the .tmp file",
        ));
    }

    if let Some(u) = unlock {
        match check_backup(path, u) {
            Ok(_) => out.push(f(
                Check::Opens,
                Level::Info,
                "the store opens and every entry decrypts",
            )),
            Err(
                StoreError::WrongPassphrase
                | StoreError::WrongRecoveryKey
                | StoreError::OsWrapFailed,
            ) => out.push(f(
                Check::Opens,
                Level::Fail,
                "that unlock did not open the store: check it, or use another way to open it",
            )),
            Err(_) => out.push(f(
                Check::Opens,
                Level::Fail,
                "the store opens but its contents are damaged: restore the latest backup",
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::KdfParams;
    use crate::value::SecretValue;
    use std::collections::BTreeMap;

    const FAST: KdfParams = KdfParams {
        m_kib: 8,
        t: 1,
        p: 1,
    };
    const VALUE: &str = "CANARY-maintain-value-3e7a90";
    const PASS: &str = "CANARY-maintain-pass-81c4d2";

    fn pass() -> SecretValue {
        SecretValue::from_string(PASS.into())
    }

    fn make(dir: &Path) -> PathBuf {
        let path = dir.join("s.secretant");
        let mut s = FileStore::create_with_params(&path, &pass(), FAST).unwrap();
        s.put(
            "db",
            SecretValue::from_string(VALUE.into()),
            BTreeMap::new(),
        )
        .unwrap();
        s.put(
            "db",
            SecretValue::from_string("second".into()),
            BTreeMap::new(),
        )
        .unwrap();
        path
    }

    #[test]
    fn backup_is_ciphertext_private_and_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let dest = dir.path().join("b.secretant");
        backup(&path, &dest).unwrap();
        let bytes = fs::read(&dest).unwrap();
        assert_eq!(
            bytes,
            fs::read(&path).unwrap(),
            "a backup is the store as it is"
        );
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains(VALUE) && !text.contains(PASS));
        assert!(is_private(&dest));
        assert_eq!(backup(&path, &dest).err(), Some(StoreError::AlreadyExists));
        // not a store: refused before anything is written
        let junk = dir.path().join("junk");
        fs::write(&junk, b"not a store").unwrap();
        assert_eq!(
            backup(&junk, &dir.path().join("b2")).err(),
            Some(StoreError::Corrupt)
        );
        assert!(!dir.path().join("b2").exists());
    }

    #[test]
    fn a_good_backup_checks_and_restores_and_a_flipped_byte_fails_loudly() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let dest = dir.path().join("b.secretant");
        backup(&path, &dest).unwrap();
        let p = pass();
        assert_eq!(
            check_backup(&dest, Unlock::Passphrase(&p)).unwrap(),
            BackupSummary {
                entries: 1,
                versions: 2
            }
        );

        // Known-bad control: every flipped ciphertext byte must fail, never succeed.
        let good = fs::read(&dest).unwrap();
        let text = String::from_utf8(good.clone()).unwrap();
        let at = text.find("\"ciphertext\"").unwrap() + 20;
        let mut bad = good.clone();
        bad[at] = if bad[at] == b'a' { b'b' } else { b'a' };
        let bad_path = dir.path().join("bad.secretant");
        fs::write(&bad_path, &bad).unwrap();
        assert!(check_backup(&bad_path, Unlock::Passphrase(&p)).is_err());
        // and restore refuses it, leaving the target alone
        let target = dir.path().join("restored.secretant");
        assert!(restore(&bad_path, &target, Unlock::Passphrase(&p), false).is_err());
        assert!(!target.exists());

        // the good one restores, then reads back
        restore(&dest, &target, Unlock::Passphrase(&p), false).unwrap();
        let s = FileStore::open(&target, &p).unwrap();
        assert_eq!(s.get("db").unwrap().expose(), b"second");
        assert_eq!(s.get_version("db", 1).unwrap().expose(), VALUE.as_bytes());
    }

    #[test]
    fn restore_never_replaces_unless_asked_and_keeps_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let dest = dir.path().join("b.secretant");
        backup(&path, &dest).unwrap();
        let p = pass();
        assert_eq!(
            restore(&dest, &path, Unlock::Passphrase(&p), false).err(),
            Some(StoreError::AlreadyExists)
        );
        let before = fs::read(&path).unwrap();
        restore(&dest, &path, Unlock::Passphrase(&p), true).unwrap();
        let mut prev = path.as_os_str().to_owned();
        prev.push(".prev");
        assert_eq!(fs::read(PathBuf::from(prev)).unwrap(), before);
    }

    #[test]
    fn doctor_reports_fixed_sentences_and_no_value_or_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let p = pass();
        let found = doctor(&path, Some(Unlock::Passphrase(&p)));
        let shown = format!("{found:?}");
        assert!(!shown.contains(VALUE) && !shown.contains(PASS) && !shown.contains("db"));
        let opens = found.iter().find(|x| x.check == Check::Opens).unwrap();
        assert_eq!(opens.level, Level::Info);
        // one wrap, no recovery, weak cost: three warnings
        for c in [Check::Wraps, Check::Recovery, Check::KdfCost] {
            let x = found.iter().find(|x| x.check == c).unwrap();
            assert_eq!(x.level, Level::Warn, "{c:?}");
        }
        // negative control: add a recovery wrap and the warnings go away
        let mut s = FileStore::open(&path, &p).unwrap();
        s.add_recovery_wrap().unwrap();
        let found = doctor(&path, None);
        for c in [Check::Wraps, Check::Recovery] {
            let x = found.iter().find(|x| x.check == c).unwrap();
            assert_eq!(x.level, Level::Info, "{c:?}");
        }
        assert!(found.iter().all(|x| x.check != Check::Opens));
    }

    #[test]
    fn doctor_finds_damage_loose_permissions_and_leftovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let p = pass();

        // a leftover temp file
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(PathBuf::from(&tmp), b"x").unwrap();
        let found = doctor(&path, None);
        assert!(
            found
                .iter()
                .any(|x| x.check == Check::LeftoverTemp && x.level == Level::Warn)
        );
        fs::remove_file(PathBuf::from(tmp)).unwrap();

        // a wrong unlock is a failure with advice, not a panic
        let wrong = SecretValue::from_string("nope".into());
        let found = doctor(&path, Some(Unlock::Passphrase(&wrong)));
        assert_eq!(
            found
                .iter()
                .find(|x| x.check == Check::Opens)
                .unwrap()
                .level,
            Level::Fail
        );

        // loosened permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            let found = doctor(&path, None);
            assert_eq!(
                found
                    .iter()
                    .find(|x| x.check == Check::OwnerOnly)
                    .unwrap()
                    .level,
                Level::Fail
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // damage and absence
        fs::write(&path, b"garbage").unwrap();
        let found = doctor(&path, Some(Unlock::Passphrase(&p)));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].level, Level::Fail);
        let missing = doctor(&dir.path().join("none"), None);
        assert_eq!(missing[0].level, Level::Fail);
    }

    #[test]
    fn export_bundle_and_import_are_dry_run_then_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let path = make(dir.path());
        let p = pass();
        let src = FileStore::open(&path, &p).unwrap();

        // export into a bundle with its own passphrase
        let bpass = SecretValue::from_string("CANARY-bundle-pass-5d2f".into());
        let bpath = dir.path().join("bundle.secretant");
        let mut bundle = FileStore::create_with_params(&bpath, &bpass, FAST).unwrap();
        src.export_to(&mut bundle).unwrap();
        // the bundle opens with its own passphrase only
        assert!(FileStore::open(&bpath, &p).is_err());
        let bundle = FileStore::open(&bpath, &bpass).unwrap();

        // import into an empty store: plan says new, apply adds all versions
        let tpath = dir.path().join("target.secretant");
        let mut target = FileStore::create_with_params(&tpath, &p, FAST).unwrap();
        let plan = target.plan_import(&bundle);
        assert_eq!(
            plan,
            vec![crate::store::ImportItem {
                name: "db".into(),
                exists: false,
                versions: 2
            }]
        );
        assert!(target.list().is_empty(), "a plan writes nothing");
        let r = target
            .apply_import(&bundle, crate::store::ImportConflict::Refuse)
            .unwrap();
        assert_eq!((r.added, r.replaced, r.kept), (1, 0, 0));
        assert_eq!(
            target.get_version("db", 1).unwrap().expose(),
            VALUE.as_bytes()
        );
        assert_eq!(target.get("db").unwrap().expose(), b"second");

        // importing again: a conflict, refused by default, nothing written
        let before = fs::read(&tpath).unwrap();
        assert_eq!(
            target
                .apply_import(&bundle, crate::store::ImportConflict::Refuse)
                .err(),
            Some(StoreError::Conflict)
        );
        assert_eq!(fs::read(&tpath).unwrap(), before);
        // keep leaves it; replace adds the latest as version 3 and deletes nothing
        let r = target
            .apply_import(&bundle, crate::store::ImportConflict::Keep)
            .unwrap();
        assert_eq!((r.added, r.replaced, r.kept), (0, 0, 1));
        let r = target
            .apply_import(&bundle, crate::store::ImportConflict::Replace)
            .unwrap();
        assert_eq!((r.added, r.replaced, r.kept), (0, 1, 0));
        assert_eq!(target.describe("db").unwrap().latest, 3);
        assert_eq!(
            target.get_version("db", 1).unwrap().expose(),
            VALUE.as_bytes()
        );
    }
}
