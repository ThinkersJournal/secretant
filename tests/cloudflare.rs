// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cloudflare Worker delivery against a fake API on localhost. The fake records
//! every request so the tests can say where the token and the values went.

use secretant::cf;
use secretant::{
    Action, CloudflareError, CloudflareWorker, FileStore, KdfParams, Ledger, SecretValue, State,
    Store,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOKEN: &str = "CANARYtoken0a1b2c3d4e5f6a7b8c9d";
const V1: &str = "CANARY-worker-v1-93ac10";
const V2: &str = "CANARY-worker-v2-5be7d2";
const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    headers: String,
    body: String,
}

type Handler = Box<dyn Fn(&Req) -> (u16, String) + Send + Sync>;

struct Fake {
    base: String,
    log: Arc<Mutex<Vec<Req>>>,
}

fn fake(handler: Handler) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/client/v4", listener.local_addr().unwrap());
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let (head_end, len) = loop {
                let n = c.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break (0, 0);
                }
                raw.extend_from_slice(&buf[..n]);
                if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&raw[..p]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    break (p + 4, len);
                }
            };
            if head_end == 0 {
                continue;
            }
            while raw.len() < head_end + len {
                let n = c.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            let head = String::from_utf8_lossy(&raw[..head_end]).into_owned();
            let mut first = head.lines().next().unwrap_or("").split(' ');
            let req = Req {
                method: first.next().unwrap_or("").to_string(),
                path: first.next().unwrap_or("").to_string(),
                headers: head.clone(),
                body: String::from_utf8_lossy(&raw[head_end..]).into_owned(),
            };
            let (status, body) = handler(&req);
            seen.lock().unwrap().push(req);
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = c.write_all(reply.as_bytes());
        }
    });
    Fake { base, log }
}

/// A fake Worker that remembers which secret names are set.
fn worker_fake() -> (Fake, Arc<Mutex<Vec<String>>>) {
    let names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let n = names.clone();
    let f = fake(Box::new(move |r| {
        if !r.headers.contains(&format!("Bearer {TOKEN}")) {
            return (403, r#"{"success":false,"errors":[]}"#.into());
        }
        if r.method == "GET" && r.path.ends_with("/secrets") {
            let list: Vec<_> = n
                .lock()
                .unwrap()
                .iter()
                .map(|x| serde_json::json!({"name": x, "type": "secret_text"}))
                .collect();
            return (
                200,
                serde_json::json!({"success": true, "result": list}).to_string(),
            );
        }
        if r.method == "PATCH" && r.path.ends_with("/secrets-bulk") {
            let v: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            for k in v["secrets"].as_object().unwrap().keys() {
                let mut g = n.lock().unwrap();
                if !g.contains(k) {
                    g.push(k.clone());
                }
            }
            return (200, r#"{"success":true,"result":{}}"#.into());
        }
        (404, "{}".into())
    }));
    (f, names)
}

struct Rig {
    dir: tempfile::TempDir,
    store: FileStore,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let pw = SecretValue::from_string("pw".into());
    let mut store =
        FileStore::create_with_params(dir.path().join("s.secretant"), &pw, FAST).unwrap();
    let put = |s: &mut FileStore, n: &str, v: &str| {
        s.put(n, SecretValue::from_string(v.into()), BTreeMap::new())
            .unwrap();
    };
    put(&mut store, "cf_token", TOKEN);
    put(&mut store, "totp_key", V1);
    Rig { dir, store }
}

fn maps() -> Vec<cf::Mapping> {
    vec![("totp_key".into(), "TOTP_ENCRYPTION_KEY".into())]
}

fn worker(f: &Fake) -> CloudflareWorker {
    CloudflareWorker::new("acct123", "humboldt").with_base_url(f.base.clone())
}

#[test]
fn apply_sends_the_value_only_in_the_body_and_the_token_only_in_the_header() {
    let r = rig();
    let (f, names) = worker_fake();
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let w = worker(&f);

    let sent = cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap();
    assert_eq!(sent, 1);
    assert_eq!(names.lock().unwrap().as_slice(), ["TOTP_ENCRYPTION_KEY"]);

    let log = f.log.lock().unwrap().clone();
    // a list first (token check), then one bulk write
    assert_eq!(log[0].method, "GET");
    assert_eq!(log[1].method, "PATCH");
    assert_eq!(log.len(), 2);
    for q in &log {
        assert!(q.headers.contains(&format!("Bearer {TOKEN}")));
        assert!(
            !q.path.contains(TOKEN) && !q.path.contains(V1),
            "URL leaked: {}",
            q.path
        );
        assert!(!q.body.contains(TOKEN), "the token went in a body");
        // the token appears once in the headers, in Authorization
        assert_eq!(q.headers.matches(TOKEN).count(), 1);
    }
    assert!(log[1].body.contains(V1), "the value must reach Cloudflare");
    assert!(!log[0].body.contains(V1));
    assert!(
        log[0]
            .path
            .contains("/accounts/acct123/workers/scripts/humboldt/secrets")
    );
}

#[test]
fn verify_says_set_or_unset_and_stale_after_rotation_and_never_a_value() {
    let mut r = rig();
    let (f, _names) = worker_fake();
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let w = worker(&f);

    let v = cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap();
    assert_eq!(v, vec![(0, State::Missing)]);
    assert_eq!(
        cf::plan(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, Action::Create)]
    );
    cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap();
    assert_eq!(
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, State::InSync)]
    );
    // nothing to send now: no write request is made
    let before = f.log.lock().unwrap().len();
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap(),
        0
    );
    let after = f.log.lock().unwrap().clone();
    assert!(after[before..].iter().all(|q| q.method == "GET"));

    // rotate: stale until applied again
    r.store
        .put(
            "totp_key",
            SecretValue::from_string(V2.into()),
            BTreeMap::new(),
        )
        .unwrap();
    assert_eq!(
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, State::Stale)]
    );
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap(),
        1
    );
    let last = f.log.lock().unwrap().last().unwrap().clone();
    assert!(last.body.contains(V2) && !last.body.contains(V1));
    // list responses never carry a value, and our reports never show one
    let shown = format!(
        "{:?}",
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap()
    );
    assert!(!shown.contains(V1) && !shown.contains(V2) && !shown.contains(TOKEN));
}

#[test]
fn a_token_without_scope_is_denied_before_any_value_leaves() {
    let mut r = rig();
    // a wrong token is stored; the fake refuses it
    r.store
        .put(
            "cf_token",
            SecretValue::from_string("CANARYwrongtoken000".into()),
            BTreeMap::new(),
        )
        .unwrap();
    let (f, names) = worker_fake();
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let e = cf::apply(&r.store, &mut ledger, &worker(&f), "cf_token", &maps()).unwrap_err();
    assert_eq!(e, CloudflareError::Denied);
    assert!(names.lock().unwrap().is_empty());
    let log = f.log.lock().unwrap().clone();
    assert!(
        log.iter().all(|q| q.method == "GET"),
        "no write may be attempted after the check fails"
    );
    assert!(log.iter().all(|q| !q.body.contains(V1)));
    assert!(!e.to_string().contains("CANARY"));
}

#[test]
fn a_read_only_token_passes_the_check_but_a_rejected_write_records_nothing() {
    let r = rig();
    // GET works, PATCH is forbidden (a token with a read scope only)
    let f = fake(Box::new(|q| {
        if q.method == "GET" {
            (200, r#"{"success":true,"result":[]}"#.into())
        } else {
            (
                403,
                // an error body that echoes the secret must never reach our error
                format!(r#"{{"success":false,"errors":[{{"message":"{V1}"}}]}}"#),
            )
        }
    }));
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let w = worker(&f);
    let e = cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap_err();
    assert_eq!(e, CloudflareError::Denied);
    assert!(!format!("{e} {e:?}").contains(V1));
    // still stale: nothing was recorded
    assert_eq!(
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, State::Missing)]
    );
}

#[test]
fn server_errors_unreachable_and_timeouts_are_their_own_classes() {
    let r = rig();
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();

    let f500 = fake(Box::new(|_| (500, "boom".into())));
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &worker(&f500), "cf_token", &maps()).unwrap_err(),
        CloudflareError::Rejected
    );
    let f404 = fake(Box::new(|_| (404, "{}".into())));
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &worker(&f404), "cf_token", &maps()).unwrap_err(),
        CloudflareError::NotFound
    );
    let f429 = fake(Box::new(|_| (429, "{}".into())));
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &worker(&f429), "cf_token", &maps()).unwrap_err(),
        CloudflareError::RateLimited
    );

    // nothing listens here
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/client/v4", dead.local_addr().unwrap());
    drop(dead);
    let w = CloudflareWorker::new("a", "s").with_base_url(base);
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap_err(),
        CloudflareError::Unreachable
    );

    // a server that answers too slowly
    let slow = fake(Box::new(|_| {
        std::thread::sleep(Duration::from_millis(1500));
        (200, r#"{"success":true,"result":[]}"#.into())
    }));
    let w = worker(&slow).with_timeout(Duration::from_millis(300));
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap_err(),
        CloudflareError::TimedOut
    );
}

#[test]
fn unusable_names_and_too_many_secrets_are_refused_without_a_request() {
    let r = rig();
    let (f, _) = worker_fake();
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let bad: Vec<cf::Mapping> = vec![("totp_key".into(), "1 BAD".into())];
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &worker(&f), "cf_token", &bad).unwrap_err(),
        CloudflareError::Unsupported
    );
    let v = SecretValue::from_string("x".into());
    let many: Vec<(&str, &SecretValue)> = (0..=secretant::MAX_BULK).map(|_| ("A", &v)).collect();
    let t = SecretValue::from_string(TOKEN.into());
    assert_eq!(
        worker(&f).put_all(&t, &many).unwrap_err(),
        CloudflareError::Unsupported
    );
    assert!(
        f.log.lock().unwrap().iter().all(|q| q.method != "PATCH"),
        "an unusable request must not be sent"
    );
}

#[test]
fn a_failed_rotation_stays_stale_and_the_next_apply_completes_it() {
    let mut r = rig();
    let names: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let allow = Arc::new(AtomicBool::new(true));
    let (n, a) = (names.clone(), allow.clone());
    let f = fake(Box::new(move |q| {
        if q.method == "GET" {
            let list: Vec<_> = n
                .lock()
                .unwrap()
                .iter()
                .map(|x| serde_json::json!({"name": x, "type": "secret_text"}))
                .collect();
            return (
                200,
                serde_json::json!({"success": true, "result": list}).to_string(),
            );
        }
        if !a.load(Ordering::SeqCst) {
            return (500, "{}".into());
        }
        let v: serde_json::Value = serde_json::from_str(&q.body).unwrap();
        for k in v["secrets"].as_object().unwrap().keys() {
            n.lock().unwrap().push(k.clone());
        }
        (200, r#"{"success":true,"result":{}}"#.into())
    }));
    let mut ledger = Ledger::open(r.dir.path().join("l.json")).unwrap();
    let w = worker(&f);
    cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap();
    r.store
        .put(
            "totp_key",
            SecretValue::from_string(V2.into()),
            BTreeMap::new(),
        )
        .unwrap();
    allow.store(false, Ordering::SeqCst);
    assert!(cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).is_err());
    // the secret is still set (with the old value), and we know it is old
    assert_eq!(
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, State::Stale)]
    );
    allow.store(true, Ordering::SeqCst);
    assert_eq!(
        cf::apply(&r.store, &mut ledger, &w, "cf_token", &maps()).unwrap(),
        1
    );
    assert_eq!(
        cf::verify(&r.store, &ledger, &w, "cf_token", &maps()).unwrap(),
        vec![(0, State::InSync)]
    );
}
