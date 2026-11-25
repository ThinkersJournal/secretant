// SPDX-License-Identifier: MIT OR Apache-2.0
//! The required test (board 498 A): a value can never appear in any response,
//! log line or the face's own record. A canary is put in the store, every tool
//! and every error path is driven, and the canary (plain, base64, hex, URL
//! encoded) must be in none of what the agent or an operator can read.

use secretant::{FileStore, KdfParams, SecretValue, Store, StoreError, Unlock};
use secretant_mcp::{
    AllowRoot, ConfigError, Decision, DenyAll, Face, HostConfig, PlacementApprover,
    PlacementRequest,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const CANARY: &str = "CANARY-face-9f3a71c2e8b4d605";
const CANARY2: &str = "CANARY-face-line\nbreak-77d1";
const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
struct Capture;
impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        LOG.lock().unwrap().push(format!("{}", r.args()));
    }
    fn flush(&self) {}
}

fn b64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn url(b: &[u8]) -> String {
    b.iter()
        .map(|x| {
            if x.is_ascii_alphanumeric() || *x == b'-' {
                (*x as char).to_string()
            } else {
                format!("%{x:02X}")
            }
        })
        .collect()
}

/// Every form a leak could take, for both canaries.
fn forms() -> Vec<String> {
    let mut v = Vec::new();
    for c in [CANARY, CANARY2] {
        let b = c.as_bytes();
        v.extend([c.to_string(), b64(b), hex(b), url(b), hex(b).to_uppercase()]);
        // The value's distinctive middle, in case of a partial.
        v.push(c.split('-').nth(2).unwrap().to_string());
    }
    v.retain(|s| !s.is_empty());
    v
}

struct Fixed(Decision);
impl PlacementApprover for Fixed {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        self.0
    }
}
struct Panics;
impl PlacementApprover for Panics {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        panic!("approver failed")
    }
}
/// Remembers what it was shown: names, paths, never a value.
struct Spy(Mutex<Vec<PlacementRequest>>);
impl PlacementApprover for Spy {
    fn approve(&self, r: &PlacementRequest) -> Decision {
        self.0.lock().unwrap().push(r.clone());
        Decision::Approved
    }
}

struct Rig {
    dir: tempfile::TempDir,
    store: PathBuf,
    safe: PathBuf,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("s.secretant");
    let pw = SecretValue::from_string("pw".into());
    let mut s = FileStore::create_with_params(&store, &pw, FAST).unwrap();
    for (n, v) in [
        ("proj_db", CANARY),
        ("proj_lines", CANARY2),
        ("other_hidden", CANARY),
    ] {
        s.put(n, SecretValue::from_string(v.into()), BTreeMap::new())
            .unwrap();
    }
    let safe = dir.path().join("safe");
    std::fs::create_dir(&safe).unwrap();
    Rig { dir, store, safe }
}

fn opener(store: &Path) -> secretant_mcp::Opener {
    let store = store.to_path_buf();
    Box::new(move || {
        let pw = SecretValue::from_string("pw".into());
        FileStore::open_with(&store, Unlock::Passphrase(&pw)).map(|s| Box::new(s) as Box<dyn Store>)
    })
}

fn face(r: &Rig, approver: Box<dyn PlacementApprover>, unreadable: bool) -> Face {
    let cfg = HostConfig::new(
        "lane-x",
        &["proj_"],
        vec![AllowRoot {
            path: r.safe.clone(),
            agent_unreadable: unreadable,
        }],
        r.dir.path().join("ledger.json"),
        r.dir.path().join("face-record.jsonl"),
    )
    .unwrap();
    Face::new(cfg, opener(&r.store), approver)
}

fn p(name: &str, path: &Path) -> Value {
    json!({"name": name, "path": path.to_string_lossy()})
}

#[test]
fn no_value_in_any_response_log_or_record() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
    let r = rig();
    let mut seen: Vec<String> = Vec::new();
    let mut run = |f: &Face, tool: &str, args: Value| -> Value {
        let v = f.call(tool, &args);
        seen.push(v.to_string());
        v
    };

    let ok = face(&r, Box::new(Fixed(Decision::Approved)), true);
    let out = r.safe.join("db.secret");

    // list: only the role's prefix, and the hidden name is absent.
    let v = run(&ok, "list_names", json!({}));
    assert_eq!(v["names"], json!(["proj_db", "proj_lines"]));

    // verify before placing, in scope and out of scope, bad and unlisted paths.
    let v = run(
        &ok,
        "verify_placement",
        json!({"placements": [
            p("proj_db", &out), p("other_hidden", &out), p("proj_db", Path::new("relative/x")),
            p("proj_db", &r.dir.path().join("outside.secret")),
        ]}),
    );
    let st: Vec<_> = v["placements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        st,
        ["missing", "out-of-scope", "bad-path", "path-not-allowed"]
    );

    // deliver: approved. The canary reaches the file, and only the file.
    let v = run(&ok, "deliver", json!({"placements": [p("proj_db", &out)]}));
    assert_eq!(v["placements"][0]["status"], "placed");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        CANARY,
        "the canary was really in play"
    );
    let v = run(
        &ok,
        "verify_placement",
        json!({"placements": [p("proj_db", &out)]}),
    );
    assert_eq!(v["placements"][0]["status"], "in-sync");
    let v = run(&ok, "ledger_read", json!({}));
    assert_eq!(v["rows"].as_array().unwrap().len(), 1);

    // env file, a bad variable, and a value that cannot fit an env line.
    let env = r.safe.join("app.env");
    let v = run(
        &ok,
        "deliver",
        json!({"placements": [
            {"name": "proj_db", "path": env.to_string_lossy(), "var": "DATABASE_URL"},
            {"name": "proj_db", "path": env.to_string_lossy(), "var": "1 bad"},
            {"name": "proj_lines", "path": env.to_string_lossy(), "var": "LINES"},
            p("proj_missing", &r.safe.join("m.secret")),
        ]}),
    );
    let st: Vec<_> = v["placements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["status"].as_str().unwrap())
        .collect();
    assert_eq!(st, ["placed", "unsupported", "unsupported", "no-such-name"]);

    // refusals: denied, timed out, no channel, and an approver that panics.
    for d in [Decision::Denied, Decision::TimedOut, Decision::Unavailable] {
        let f = face(&r, Box::new(Fixed(d)), true);
        let v = run(
            &f,
            "deliver",
            json!({"placements": [p("proj_db", &r.safe.join("never.secret"))]}),
        );
        assert_ne!(v["placements"][0]["status"], "placed");
    }
    let f = face(&r, Box::new(Panics), true);
    let v = run(
        &f,
        "deliver",
        json!({"placements": [p("proj_db", &r.safe.join("never.secret"))]}),
    );
    assert_eq!(v["placements"][0]["status"], "approval-unavailable");
    let f = face(&r, Box::new(DenyAll), true);
    run(
        &f,
        "deliver",
        json!({"placements": [p("proj_db", &r.safe.join("never.secret"))]}),
    );
    assert!(
        !r.safe.join("never.secret").exists(),
        "a refusal writes nothing"
    );

    // a root the host did not declare agent-unreadable: refused, nothing written.
    let f = face(&r, Box::new(Fixed(Decision::Approved)), false);
    let v = run(
        &f,
        "deliver",
        json!({"placements": [p("proj_db", &r.safe.join("open.secret"))]}),
    );
    assert_eq!(v["placements"][0]["status"], "path-not-allowed");
    assert!(!r.safe.join("open.secret").exists());

    // unknown tools (a get, a put, an export) and malformed arguments.
    for t in ["get", "put", "export", "run", "list_names2", ""] {
        let v = run(&ok, t, json!({"name": "proj_db"}));
        assert_eq!(v["error"], "bad-request", "no tool named {t:?}");
    }
    run(&ok, "deliver", json!({"placements": "not a list"}));

    // the store cannot be opened (locked, wrong unlock, gone).
    let locked = Face::new(
        HostConfig::new(
            "lane-x",
            &["proj_"],
            vec![],
            r.dir.path().join("l.json"),
            r.dir.path().join("rec2.jsonl"),
        )
        .unwrap(),
        Box::new(|| Err(StoreError::WrongPassphrase)),
        Box::new(DenyAll),
    );
    assert_eq!(
        run(&locked, "list_names", json!({}))["error"],
        "store-error"
    );

    // the face's record cannot be written: the call stops, nothing is done.
    let bad = Face::new(
        HostConfig::new(
            "lane-x",
            &["proj_"],
            vec![AllowRoot {
                path: r.safe.clone(),
                agent_unreadable: true,
            }],
            r.dir.path().join("l2.json"),
            r.safe.clone(),
        )
        .unwrap(),
        opener(&r.store),
        Box::new(Fixed(Decision::Approved)),
    );
    let v = run(
        &bad,
        "deliver",
        json!({"placements": [p("proj_db", &r.safe.join("x.secret"))]}),
    );
    assert_eq!(v["error"], "record-failed");
    assert!(!r.safe.join("x.secret").exists());

    // The sinks: every response, every log line, the record file.
    let record = std::fs::read_to_string(r.dir.path().join("face-record.jsonl")).unwrap();
    assert!(
        record.lines().count() > 10 && record.contains("lane-x"),
        "the record is being written"
    );
    let logs = LOG.lock().unwrap().join("\n");
    for f in forms() {
        for (what, text) in [
            ("a response", seen.join("\n")),
            ("the log", logs.clone()),
            ("the record", record.clone()),
        ] {
            assert!(!text.contains(&f), "a value form {f:?} reached {what}");
        }
    }
}

#[test]
fn the_approver_sees_names_and_paths_only() {
    let r = rig();
    let spy = std::sync::Arc::new(Spy(Mutex::new(Vec::new())));
    struct Shared(std::sync::Arc<Spy>);
    impl PlacementApprover for Shared {
        fn approve(&self, q: &PlacementRequest) -> Decision {
            self.0.approve(q)
        }
    }
    let f = face(&r, Box::new(Shared(spy.clone())), true);
    let _ = f.call(
        "deliver",
        &json!({"placements": [p("proj_db", &r.safe.join("a.secret"))]}),
    );
    let shown = format!("{:?}", spy.0.lock().unwrap());
    assert!(shown.contains("proj_db") && shown.contains("a.secret"));
    for f in forms() {
        assert!(!shown.contains(&f));
    }
}

#[test]
fn no_role_no_face() {
    let c =
        |role: &str, pre: &[&str]| HostConfig::new(role, pre, vec![], "l".into(), "r".into()).err();
    assert_eq!(c("", &["a_"]), Some(ConfigError::NoRole));
    assert_eq!(c("lane", &[]), Some(ConfigError::NoRole));
    assert_eq!(c("lane", &[""]), Some(ConfigError::NoRole));
    assert_eq!(c("lane", &["a_"]), None);
}

#[test]
fn a_symlink_or_junction_escape_fails_closed() {
    let r = rig();
    let f = face(&r, Box::new(Fixed(Decision::Approved)), true);
    let outside = r.dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();

    // A directory link inside the root pointing out of it.
    let link = r.safe.join("escape");
    let made = {
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(&outside)
                .output()
                .is_ok_and(|o| o.status.success())
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &link).is_ok()
        }
    };
    assert!(
        made,
        "could not create the directory link, so this test proved nothing"
    );
    let v = f.call(
        "deliver",
        &json!({"placements": [p("proj_db", &link.join("x.secret"))]}),
    );
    assert_eq!(v["placements"][0]["status"], "path-not-allowed");
    assert!(!outside.join("x.secret").exists());

    // A file link inside the root pointing at a file outside it.
    let target = outside.join("victim");
    std::fs::write(&target, "old").unwrap();
    let flink = r.safe.join("filelink");
    #[cfg(unix)]
    let ok = std::os::unix::fs::symlink(&target, &flink).is_ok();
    #[cfg(windows)]
    let ok = std::os::windows::fs::symlink_file(&target, &flink).is_ok();
    if ok {
        let v = f.call("deliver", &json!({"placements": [p("proj_db", &flink)]}));
        assert_eq!(v["placements"][0]["status"], "path-not-allowed");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");
    } else {
        eprintln!(
            "file symlink not creatable here (needs privilege); junction case above still ran"
        );
    }
}

#[test]
fn a_delivered_file_is_owner_only_and_checked() {
    let r = rig();
    let f = face(&r, Box::new(Fixed(Decision::Approved)), true);
    let out = r.safe.join("k.secret");
    let v = f.call("deliver", &json!({"placements": [p("proj_db", &out)]}));
    assert_eq!(v["placements"][0]["status"], "placed");
    // `verify` answers in-sync only when the file is owner-only (mode 0o077
    // clear on Unix; on Windows the ACL holds only the current user, read back
    // with icacls): that is the check rule 4 rests on.
    let v = f.call(
        "verify_placement",
        &json!({"placements": [p("proj_db", &out)]}),
    );
    assert_eq!(v["placements"][0]["status"], "in-sync");
}

#[test]
fn paths_compare_exact_case_and_long_paths_are_refused_whole() {
    let r = rig();
    let f = face(&r, Box::new(Fixed(Decision::Approved)), true);
    // A path component over the OS limit is refused, never clipped.
    let long = r.safe.join("a".repeat(400));
    let v = f.call("deliver", &json!({"placements": [p("proj_db", &long)]}));
    assert_ne!(v["placements"][0]["status"], "placed");
    // The path shown to the approver is the canonical path, as given in case.
    let spy = std::sync::Arc::new(Spy(Mutex::new(Vec::new())));
    struct Shared(std::sync::Arc<Spy>);
    impl PlacementApprover for Shared {
        fn approve(&self, q: &PlacementRequest) -> Decision {
            self.0.approve(q)
        }
    }
    let f = face(&r, Box::new(Shared(spy.clone())), true);
    let _ = f.call(
        "deliver",
        &json!({"placements": [p("proj_db", &r.safe.join("MixedCase.Secret"))]}),
    );
    let shown = spy.0.lock().unwrap();
    assert_eq!(shown[0].path.file_name().unwrap(), "MixedCase.Secret");
}
