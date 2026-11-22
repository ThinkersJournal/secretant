// SPDX-License-Identifier: MIT OR Apache-2.0
//! The installer Store step: a crash never leaves a store whose recovery key
//! nobody confirmed, an existing store is never duplicated, a stale plan is
//! refused, and no secret is in any file in any common encoding.

use secretant::installer::{
    InstallError, StoreAction, StoreApplied, StoreProbe, apply_store, confirm_recovery,
    discard_pending, pending_path, plan_store, probe_store, read_back_store,
};
use secretant::{FileStore, SecretValue, Unlock};
use std::path::{Path, PathBuf};

const PASS: &str = "CANARY-install-pass-61c4";

fn pass(s: &str) -> SecretValue {
    SecretValue::from_string(s.to_string())
}

fn dir_and_path() -> (tempfile::TempDir, PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("store.json");
    (d, p)
}

fn prev_of(p: &Path) -> PathBuf {
    let mut s = pending_path(p).into_os_string();
    s.push(".prev");
    PathBuf::from(s)
}

/// Plan and apply a creation; returns the pending store and the key text.
fn begin(path: &Path) -> (secretant::installer::PendingStore, String) {
    let plan = plan_store(path, probe_store(path), false);
    match apply_store(&plan, &pass(PASS)).unwrap() {
        StoreApplied::Pending {
            store,
            recovery_key,
        } => (
            store,
            String::from_utf8(recovery_key.expose().to_vec()).unwrap(),
        ),
        _ => panic!("expected a pending store"),
    }
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn forms(s: &str) -> Vec<Vec<u8>> {
    let bare: String = s.chars().filter(|c| *c != '-').collect();
    let hex = |t: &str| -> String { t.bytes().map(|b| format!("{b:02x}")).collect() };
    let mut v = Vec::new();
    for t in [s.to_string(), bare, s.to_uppercase(), s.to_lowercase()] {
        v.push(t.clone().into_bytes());
        v.push(hex(&t).into_bytes());
        v.push(b64(t.as_bytes()).into_bytes());
        v.push(t.encode_utf16().flat_map(u16::to_le_bytes).collect());
    }
    v
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_new_store_exists_only_after_the_typed_back_key_opens_it() {
    let (_d, path) = dir_and_path();
    assert_eq!(probe_store(&path), StoreProbe::Absent);
    let (pending, key) = begin(&path);
    assert_eq!(key.len(), 71, "64 hex digits in 8 groups");
    // Until the key is confirmed there is no store, only the pending file.
    assert!(!path.exists());
    assert!(pending_path(&path).exists());
    assert_eq!(probe_store(&path), StoreProbe::Pending);

    // A mistyped key finishes nothing; the pending file stays for another try.
    let mut wrong = key.clone();
    wrong.replace_range(0..1, if key.starts_with('0') { "1" } else { "0" });
    assert_eq!(
        confirm_recovery(&pending, &pass(&wrong)).err(),
        Some(InstallError::RecoveryNotConfirmed)
    );
    assert!(!path.exists());
    assert!(pending_path(&path).exists());
    // The password is not the key.
    assert_eq!(
        confirm_recovery(&pending, &pass(PASS)).err(),
        Some(InstallError::RecoveryNotConfirmed)
    );
    assert!(!path.exists());

    confirm_recovery(&pending, &pass(&key)).unwrap();
    assert!(path.exists());
    assert!(!pending_path(&path).exists());
    assert!(!prev_of(&path).exists(), "no leftover generation");
    let report = read_back_store(&path, Unlock::Passphrase(&pass(PASS))).unwrap();
    assert_eq!(report.wraps, ["passphrase", "recovery"]);
    assert_eq!(report.entries, 0);
    read_back_store(&path, Unlock::Recovery(&pass(&key))).unwrap();
    assert_eq!(
        read_back_store(&path, Unlock::Passphrase(&pass("not it"))).err(),
        Some(InstallError::WrongUnlock)
    );
}

#[test]
fn neither_the_key_nor_the_passphrase_is_in_any_file_in_any_form() {
    let (_d, path) = dir_and_path();
    let (pending, key) = begin(&path);
    let pending_bytes = std::fs::read(pending_path(&path)).unwrap();
    confirm_recovery(&pending, &pass(&key)).unwrap();
    let final_bytes = std::fs::read(&path).unwrap();

    // Control: the search finds text that is there.
    let mut planted = final_bytes.clone();
    planted.extend_from_slice(key.as_bytes());
    assert!(holds(&planted, key.as_bytes()));
    for bytes in [&pending_bytes, &final_bytes] {
        for secret in [key.as_str(), PASS] {
            for f in forms(secret) {
                assert!(!holds(bytes, &f), "a secret is in a store file");
            }
        }
    }
}

#[test]
fn an_unfinished_run_is_discarded_and_its_key_no_longer_opens_anything() {
    let (_d, path) = dir_and_path();
    let (first, first_key) = begin(&path);
    drop(first); // the installer stopped before the person confirmed

    // The next run sees the leftover, and offers one thing: start over.
    let probe = probe_store(&path);
    assert_eq!(probe, StoreProbe::Pending);
    let plan = plan_store(&path, probe, false);
    assert_eq!(
        plan.action,
        StoreAction::DiscardPendingAndCreate { os_wrap: false }
    );
    let StoreApplied::Pending {
        store,
        recovery_key,
    } = apply_store(&plan, &pass(PASS)).unwrap()
    else {
        panic!("expected a pending store");
    };
    let second_key = String::from_utf8(recovery_key.expose().to_vec()).unwrap();
    assert_ne!(first_key, second_key);
    assert_eq!(
        confirm_recovery(&store, &pass(&first_key)).err(),
        Some(InstallError::RecoveryNotConfirmed)
    );
    confirm_recovery(&store, &pass(&second_key)).unwrap();
    assert!(path.exists());
}

#[test]
fn an_existing_store_is_used_never_duplicated_and_left_byte_for_byte() {
    let (_d, path) = dir_and_path();
    let mut s = FileStore::create(&path, &pass(PASS)).unwrap();
    s.add_recovery_wrap().unwrap();
    drop(s);
    let before = std::fs::read(&path).unwrap();

    let probe = probe_store(&path);
    assert!(matches!(probe, StoreProbe::Present(_)));
    let plan = plan_store(&path, probe, false);
    assert_eq!(plan.action, StoreAction::UseExisting);
    assert!(matches!(
        apply_store(&plan, &pass("ignored")).unwrap(),
        StoreApplied::Unchanged
    ));
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert!(!pending_path(&path).exists());
}

#[test]
fn a_plan_made_before_the_store_appeared_is_refused() {
    let (_d, path) = dir_and_path();
    let stale = plan_store(&path, probe_store(&path), false);
    assert_eq!(stale.action, StoreAction::Create { os_wrap: false });
    // Someone else installs first.
    FileStore::create(&path, &pass("theirs")).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        apply_store(&stale, &pass(PASS)).err(),
        Some(InstallError::StalePlan)
    );
    assert_eq!(before, std::fs::read(&path).unwrap());
    assert!(!pending_path(&path).exists());
}

#[test]
fn an_empty_passphrase_writes_nothing() {
    let (_d, path) = dir_and_path();
    let plan = plan_store(&path, probe_store(&path), false);
    assert_eq!(
        apply_store(&plan, &pass("")).err(),
        Some(InstallError::EmptyPassphrase)
    );
    assert!(!path.exists());
    assert!(!pending_path(&path).exists());
}

#[test]
fn a_file_that_is_not_a_store_is_refused_and_left_alone() {
    let (_d, path) = dir_and_path();
    std::fs::write(&path, b"not a store").unwrap();
    let plan = plan_store(&path, probe_store(&path), false);
    assert_eq!(plan.action, StoreAction::Refuse(InstallError::Damaged));
    assert_eq!(
        apply_store(&plan, &pass(PASS)).err(),
        Some(InstallError::Damaged)
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not a store");
}

#[test]
fn discarding_never_touches_a_real_store() {
    let (_d, path) = dir_and_path();
    FileStore::create(&path, &pass(PASS)).unwrap();
    let before = std::fs::read(&path).unwrap();
    discard_pending(&path).unwrap();
    assert_eq!(before, std::fs::read(&path).unwrap());
}

#[cfg(any(
    windows,
    all(feature = "os-keystore", any(target_os = "macos", target_os = "linux"))
))]
#[test]
fn the_os_bound_wrap_is_added_when_asked() {
    let (_d, path) = dir_and_path();
    let plan = plan_store(&path, probe_store(&path), true);
    assert_eq!(plan.action, StoreAction::Create { os_wrap: true });
    let StoreApplied::Pending {
        store,
        recovery_key,
    } = (match apply_store(&plan, &pass(PASS)) {
        Ok(applied) => applied,
        // No OS key store here (a plain `--all-features` run): skip, loudly. The CI
        // jobs in os-store-probe.yml set SECRETANT_OS_WRAP_REQUIRED=1.
        Err(e) if !cfg!(windows) && std::env::var_os("SECRETANT_OS_WRAP_REQUIRED").is_none() => {
            eprintln!("skipped: no OS key store ({e:?})");
            return;
        }
        Err(e) => panic!("the OS key store is required here: {e:?}"),
    })
    else {
        panic!("expected a pending store");
    };
    confirm_recovery(&store, &recovery_key).unwrap();
    let r = read_back_store(&path, Unlock::Os).unwrap();
    let kind = if cfg!(windows) {
        "os-dpapi"
    } else {
        "os-keystore"
    };
    // Linux without a Secret Service falls back to `systemd-creds`.
    let ok = r.wraps == ["passphrase", kind, "recovery"]
        || (cfg!(target_os = "linux") && r.wraps == ["passphrase", "os-systemd-creds", "recovery"]);
    assert!(ok, "unexpected wraps: {:?}", r.wraps);
}

#[cfg(not(any(
    windows,
    all(feature = "os-keystore", any(target_os = "macos", target_os = "linux"))
)))]
#[test]
fn the_os_bound_wrap_is_refused_not_silently_dropped_elsewhere() {
    let (_d, path) = dir_and_path();
    let plan = plan_store(&path, probe_store(&path), true);
    assert_eq!(
        plan.action,
        StoreAction::Refuse(InstallError::OsWrapUnavailable)
    );
}
