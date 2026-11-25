// SPDX-License-Identifier: MIT OR Apache-2.0
//! Items 3-5: the interim gate is named and on every record line; roots fail
//! closed unless declared agent-unreadable; owner-only is checked on both
//! platforms (Unix mode bits, Windows ACL read back with icacls).
use secretant::{FileStore, KdfParams, SecretValue, Store, Unlock};
use secretant_mcp::{
    AllowRoot, Decision, Face, HostConfig, INTERIM_GATE, PlacementApprover, PlacementRequest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

struct Yes;
impl PlacementApprover for Yes {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        Decision::Approved
    }
}

struct Rig {
    dir: tempfile::TempDir,
    safe: PathBuf,
    open: PathBuf,
}

fn rig() -> (Rig, Face) {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("s.secretant");
    let pw = SecretValue::from_string("pw".into());
    let mut s = FileStore::create_with_params(
        &store,
        &pw,
        KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    s.put(
        "proj_db",
        SecretValue::from_string("CANARY-gate-61d2".into()),
        BTreeMap::new(),
    )
    .unwrap();
    s.put(
        "zzz_other",
        SecretValue::from_string("CANARY-gate-61d2".into()),
        BTreeMap::new(),
    )
    .unwrap();
    let safe = dir.path().join("safe");
    let open = dir.path().join("open");
    std::fs::create_dir(&safe).unwrap();
    std::fs::create_dir(&open).unwrap();
    let cfg = HostConfig::new(
        "lane-x",
        &["proj_"],
        vec![
            AllowRoot {
                path: safe.clone(),
                agent_unreadable: true,
            },
            AllowRoot {
                path: open.clone(),
                agent_unreadable: false,
            },
        ],
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
        Box::new(Yes),
    );
    (Rig { dir, safe, open }, face)
}

fn status(f: &Face, tool: &str, name: &str, path: &Path) -> String {
    let v: Value = f.call(
        tool,
        &json!({"placements":[{"name":name,"path":path.to_string_lossy()}]}),
    );
    v["placements"][0]["status"]
        .as_str()
        .unwrap_or("?")
        .to_string()
}

#[test]
fn every_call_is_gated_and_the_stand_in_is_named() {
    let (r, f) = rig();
    assert!(INTERIM_GATE.contains("stand-in for permission-policy"));
    // Scope: a name outside the role's prefixes is refused on every tool that takes one.
    for t in ["verify_placement", "deliver"] {
        assert_eq!(
            status(&f, t, "zzz_other", &r.safe.join("a")),
            "out-of-scope",
            "{t}"
        );
    }
    assert_eq!(
        f.call("list_names", &json!({}))["names"],
        json!(["proj_db"])
    );
    let _ = f.call("ledger_read", &json!({}));
    // Every call, allowed or refused, is on the record with the gate that applied.
    let rec = std::fs::read_to_string(r.dir.path().join("rec.jsonl")).unwrap();
    assert!(rec.lines().count() >= 4);
    for l in rec.lines() {
        let v: Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["gate"], INTERIM_GATE, "{l}");
        assert_eq!(v["role"], "lane-x");
    }
}

#[test]
fn a_root_not_declared_agent_unreadable_is_refused_on_every_tool() {
    let (r, f) = rig();
    for t in ["verify_placement", "deliver"] {
        assert_eq!(
            status(&f, t, "proj_db", &r.open.join("k")),
            "path-not-allowed",
            "{t}"
        );
    }
    assert!(!r.open.join("k").exists());
    // And the root itself, named as a file target, is refused.
    assert_eq!(
        status(&f, "deliver", "proj_db", &r.open),
        "path-not-allowed"
    );
    // A root with no declared roots at all refuses everything.
    let none = Face::new(
        HostConfig::new(
            "lane-x",
            &["proj_"],
            vec![],
            r.dir.path().join("l2"),
            r.dir.path().join("r2"),
        )
        .unwrap(),
        Box::new(|| Err(secretant::StoreError::Io)),
        Box::new(Yes),
    );
    assert_eq!(
        status(&none, "deliver", "proj_db", &r.safe.join("k")),
        "path-not-allowed"
    );
}

#[cfg(windows)]
fn acl_principals(path: &Path) -> Vec<String> {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let prefix = path.to_string_lossy().into_owned();
    text.lines()
        .filter_map(|l| {
            let end = l.find(":(")?;
            let head = l[..end].trim();
            Some(
                head.strip_prefix(prefix.as_str())
                    .unwrap_or(head)
                    .trim()
                    .to_string(),
            )
        })
        .filter(|n| !n.is_empty())
        .collect()
}

#[test]
fn a_delivered_file_is_owner_only_and_a_loosened_one_is_reported() {
    let (r, f) = rig();
    let out = r.safe.join("k.secret");
    assert_eq!(status(&f, "deliver", "proj_db", &out), "placed");
    assert_eq!(status(&f, "verify_placement", "proj_db", &out), "in-sync");

    #[cfg(windows)]
    {
        // Read the ACL ourselves, independently of the library's check.
        let me = std::env::var("USERNAME").unwrap().to_lowercase();
        let who = acl_principals(&out);
        assert!(
            !who.is_empty() && who.iter().all(|n| n.to_lowercase().ends_with(&me)),
            "ACL holds only the owner: {who:?}"
        );
        let ok = std::process::Command::new("icacls")
            .arg(&out)
            .args(["/grant", "*S-1-1-0:R"])
            .output()
            .unwrap();
        assert!(
            ok.status.success(),
            "could not loosen the ACL, so this proved nothing"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "owner-only mode, got {mode:o}");
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    assert_eq!(
        status(&f, "verify_placement", "proj_db", &out),
        "loose-perms"
    );
    // Delivering again repairs it (the library rewrites through a private temp file).
    assert_eq!(status(&f, "deliver", "proj_db", &out), "placed");
    assert_eq!(status(&f, "verify_placement", "proj_db", &out), "in-sync");
}
