// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Place step for a Cloudflare Worker, against a fake API on localhost:
//! canaries, no-op sends nothing, stale plan, all-or-nothing, nothing leaks.

use secretant::cf;
use secretant::place_step::cloudflare::{
    CloudflarePlaceError, apply_cloudflare, plan_cloudflare, probe_cloudflare, read_back_cloudflare,
};
use secretant::{
    Action, CloudflareError, CloudflareWorker, FileStore, KdfParams, Ledger, SecretValue, State,
    Store,
};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

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
    ledger: Ledger,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let pw = SecretValue::from_string("pw".into());
    let mut store =
        FileStore::create_with_params(dir.path().join("s.secretant"), &pw, FAST).unwrap();
    for (n, v) in [("cf_token", TOKEN), ("totp_key", V1)] {
        store
            .put(n, SecretValue::from_string(v.into()), BTreeMap::new())
            .unwrap();
    }
    let ledger = Ledger::open(dir.path().join("l.json")).unwrap();
    Rig { dir, store, ledger }
}

fn maps() -> Vec<cf::Mapping> {
    vec![("totp_key".into(), "TOTP_ENCRYPTION_KEY".into())]
}

fn worker(f: &Fake) -> CloudflareWorker {
    CloudflareWorker::new("acct123", "humboldt").with_base_url(f.base.clone())
}

#[test]
fn plan_apply_and_read_back_send_the_value_once_and_show_none() {
    let mut r = rig();
    let (f, names) = worker_fake();
    let w = worker(&f);
    let plan = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    assert_eq!(plan.actions(), [(0, Action::Create)]);
    let mut shown = format!("{plan:?}");
    // The plan sent no value: only list calls so far.
    assert!(f.log.lock().unwrap().iter().all(|q| q.method == "GET"));
    let done = apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &plan).unwrap();
    shown += &format!("{done:?}");
    assert_eq!((done.sent, done.unchanged), (1, 0));
    assert_eq!(names.lock().unwrap().as_slice(), ["TOTP_ENCRYPTION_KEY"]);
    let back = read_back_cloudflare(&r.store, &r.ledger, &w, "cf_token", &maps()).unwrap();
    shown += &format!("{back:?}");
    assert_eq!(back, [(0, State::InSync)]);
    let bodies: Vec<_> = f
        .log
        .lock()
        .unwrap()
        .iter()
        .map(|q| q.body.clone())
        .collect();
    // Control: the value did reach Cloudflare, in a body, once.
    assert_eq!(bodies.iter().filter(|b| b.contains(V1)).count(), 1);
    assert!(!shown.contains(V1) && !shown.contains(TOKEN));
    assert!(shown.contains("InSync"));
    let _ = r.dir.path();
}

#[test]
fn a_rerun_sends_nothing_and_a_new_version_sends_only_that() {
    let mut r = rig();
    let (f, _names) = worker_fake();
    let w = worker(&f);
    let plan = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &plan).unwrap();
    let patches = |f: &Fake| {
        f.log
            .lock()
            .unwrap()
            .iter()
            .filter(|q| q.method == "PATCH")
            .count()
    };
    assert_eq!(patches(&f), 1);
    let again = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    assert!(again.is_noop());
    let done = apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &again).unwrap();
    assert_eq!((done.sent, done.unchanged), (0, 1));
    assert_eq!(patches(&f), 1, "a no-op must not write");
    r.store
        .put(
            "totp_key",
            SecretValue::from_string(V2.into()),
            BTreeMap::new(),
        )
        .unwrap();
    let probe = probe_cloudflare(&r.store, &r.ledger, &w, "cf_token", &maps()).unwrap();
    assert_eq!(probe, [(0, State::Stale)]);
    let plan = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    assert_eq!(plan.actions(), [(0, Action::Update)]);
    apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &plan).unwrap();
    assert_eq!(patches(&f), 2);
    assert!(f.log.lock().unwrap().last().unwrap().body.contains(V2));
}

#[test]
fn a_worker_changed_after_the_plan_is_refused_and_nothing_is_sent() {
    let mut r = rig();
    let (f, names) = worker_fake();
    let w = worker(&f);
    let plan = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    // Someone sets the secret by hand between plan and apply.
    names.lock().unwrap().push("TOTP_ENCRYPTION_KEY".into());
    assert_eq!(
        apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &plan).err(),
        Some(CloudflarePlaceError::StalePlan)
    );
    assert!(f.log.lock().unwrap().iter().all(|q| q.method == "GET"));
}

#[test]
fn a_refused_token_fails_the_plan_with_its_class_and_sends_no_value() {
    let r = rig();
    let (f, _names) = worker_fake();
    let w = worker(&f);
    let mut store = r.store;
    store
        .put(
            "cf_token",
            SecretValue::from_string("CANARYwrongtoken000000".into()),
            BTreeMap::new(),
        )
        .unwrap();
    let err = plan_cloudflare(&store, &r.ledger, &w, "cf_token", maps()).unwrap_err();
    assert_eq!(
        err,
        CloudflarePlaceError::Cloudflare(CloudflareError::Denied)
    );
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains("CANARYwrongtoken") && !shown.contains(V1));
    assert!(f.log.lock().unwrap().iter().all(|q| !q.body.contains(V1)));
}

#[test]
fn a_rejected_write_leaves_the_ledger_alone_so_the_next_plan_still_sends() {
    let mut r = rig();
    let n: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let f = fake(Box::new(move |q| {
        let _ = &n;
        if q.method == "GET" {
            (200, r#"{"success":true,"result":[]}"#.into())
        } else {
            (500, "{}".into())
        }
    }));
    let w = worker(&f);
    let plan = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    assert_eq!(
        apply_cloudflare(&r.store, &mut r.ledger, &w, "cf_token", &plan).err(),
        Some(CloudflarePlaceError::Cloudflare(CloudflareError::Rejected))
    );
    let again = plan_cloudflare(&r.store, &r.ledger, &w, "cf_token", maps()).unwrap();
    assert_eq!(again.actions(), [(0, Action::Create)]);
}
