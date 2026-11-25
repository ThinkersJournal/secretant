// SPDX-License-Identifier: MIT OR Apache-2.0
//! Item 2: exact-case paths, the canonical path bound at approval and
//! re-checked at write (a directory swapped for a junction or symlink after the
//! person approved must not redirect the write).
use secretant::{FileStore, KdfParams, SecretValue, Store, Unlock};
use secretant_mcp::{AllowRoot, Decision, Face, HostConfig, PlacementApprover, PlacementRequest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct Hook(Mutex<Option<Box<dyn FnOnce() + Send>>>);
impl PlacementApprover for Hook {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        if let Some(f) = self.0.lock().unwrap().take() {
            f();
        }
        Decision::Approved
    }
}

fn rig(approver: Box<dyn PlacementApprover>) -> (tempfile::TempDir, PathBuf, Face) {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("s.secretant");
    let pw = SecretValue::from_string("pw".into());
    FileStore::create_with_params(
        &store,
        &pw,
        KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        },
    )
    .unwrap()
    .put(
        "proj_db",
        SecretValue::from_string("CANARY-paths-3e91".into()),
        BTreeMap::new(),
    )
    .unwrap();
    let safe = dir.path().join("safe");
    std::fs::create_dir(&safe).unwrap();
    let cfg = HostConfig::new(
        "lane-x",
        &["proj_"],
        vec![AllowRoot {
            path: safe.clone(),
            agent_unreadable: true,
        }],
        dir.path().join("ledger.json"),
        dir.path().join("rec.jsonl"),
    )
    .unwrap();
    let face = Face::new(
        cfg,
        Box::new(move || {
            let pw = SecretValue::from_string("pw".into());
            FileStore::open_with(&store, Unlock::Passphrase(&pw))
                .map(|s| Box::new(s) as Box<dyn Store>)
        }),
        approver,
    );
    (dir, safe, face)
}

fn deliver(f: &Face, path: &Path) -> String {
    let v: Value = f.call(
        "deliver",
        &json!({"placements":[{"name":"proj_db","path":path.to_string_lossy()}]}),
    );
    v["placements"][0]["status"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

fn link_dir(link: &Path, target: &Path) -> bool {
    #[cfg(windows)]
    {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).is_ok()
    }
}

#[test]
fn a_path_in_the_wrong_case_is_refused_not_matched() {
    let (_d, safe, f) = rig(Box::new(Hook(Mutex::new(None))));
    assert_eq!(deliver(&f, &safe.join("Out.secret")), "placed");
    let lower = safe.join("out.secret");
    // Only where the file system folds case does `out.secret` name the same file.
    if lower.exists() {
        assert_eq!(
            deliver(&f, &lower),
            "bad-path",
            "a different case is a different path"
        );
    }
    // The directory part too: an upper-cased directory is not the approved path.
    let shout = PathBuf::from(safe.to_string_lossy().to_uppercase()).join("x.secret");
    if shout.parent().unwrap().exists() && shout != safe.join("x.secret") {
        assert_eq!(deliver(&f, &shout), "bad-path");
        assert!(!safe.join("x.secret").exists());
    }
}

#[test]
fn the_approved_path_is_the_canonical_one_and_is_shown() {
    let seen: std::sync::Arc<Mutex<Vec<PlacementRequest>>> = Default::default();
    struct Rec(std::sync::Arc<Mutex<Vec<PlacementRequest>>>);
    impl PlacementApprover for Rec {
        fn approve(&self, r: &PlacementRequest) -> Decision {
            self.0.lock().unwrap().push(r.clone());
            Decision::Approved
        }
    }
    let (_d, safe, f) = rig(Box::new(Rec(seen.clone())));
    assert_eq!(deliver(&f, &safe.join("a.secret")), "placed");
    let s = seen.lock().unwrap();
    assert_eq!(s[0].subject, format!("proj_db -> {}", s[0].path.display()));
    assert_eq!(s[0].path.file_name().unwrap(), "a.secret");
}

#[test]
fn a_directory_swapped_for_a_link_after_approval_does_not_redirect_the_write() {
    let outside = tempfile::tempdir().unwrap();
    let out_path = outside.path().to_path_buf();
    let swapped = std::sync::Arc::new(Mutex::new(PathBuf::new()));
    let sw = swapped.clone();
    let hook: Box<dyn FnOnce() + Send> = Box::new(move || {
        let sub = sw.lock().unwrap().clone();
        std::fs::remove_dir(&sub).unwrap();
        assert!(
            link_dir(&sub, &out_path),
            "could not make the link, so this proved nothing"
        );
    });
    let (_d, safe, f) = rig(Box::new(Hook(Mutex::new(Some(hook)))));
    let sub = safe.join("sub");
    std::fs::create_dir(&sub).unwrap();
    *swapped.lock().unwrap() = sub.clone();
    let status = deliver(&f, &sub.join("k.secret"));
    assert_eq!(status, "path-not-allowed");
    assert!(
        !outside.path().join("k.secret").exists(),
        "nothing was written outside the root"
    );
}
