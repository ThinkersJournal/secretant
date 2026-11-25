// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Hello approver with a fake consent channel (no person at the desktop):
//! it shows the whole subject, maps answers, and fails closed when the process
//! table cannot place the requester.
#![cfg(feature = "hello")]

use secretant::{FileStore, KdfParams, SecretValue, Store, Unlock};
use secretant_mcp::hello::HelloApprover;
use secretant_mcp::{AllowRoot, Decision, Face, HostConfig, PlacementApprover, PlacementRequest};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use user_request::Requester;
use user_request::consent::{Consent, ConsentOutcome};

struct Fake {
    answer: fn() -> ConsentOutcome,
    shown: Arc<Mutex<Vec<String>>>,
}
impl Consent for Fake {
    fn ask(&self, prompt: &str, _wait: Duration) -> ConsentOutcome {
        self.shown.lock().unwrap().push(prompt.to_string());
        (self.answer)()
    }
}

fn who() -> Requester {
    Requester {
        role: "lane-x".into(),
        session_id: "s1".into(),
        claude_pid: 4242,
        claude_start_secs: 1,
        managed: true,
    }
}

fn approver(
    who: Result<Requester, String>,
    answer: fn() -> ConsentOutcome,
) -> (HelloApprover<Fake>, Arc<Mutex<Vec<String>>>) {
    let shown: Arc<Mutex<Vec<String>>> = Arc::default();
    let s = shown.clone();
    (
        HelloApprover::with_identity(
            who,
            Box::new(move || Fake {
                answer,
                shown: s.clone(),
            }),
        ),
        shown,
    )
}

fn req(name: &str, path: &str) -> PlacementRequest {
    PlacementRequest {
        role: "lane-x".into(),
        name: name.into(),
        path: path.into(),
        var: None,
        subject: secretant_mcp::subject::format(name, std::path::Path::new(path)).unwrap(),
    }
}

#[test]
fn answers_map_and_the_whole_subject_is_shown() {
    for (answer, want) in [
        (
            ((|| ConsentOutcome::Approved) as fn() -> ConsentOutcome),
            Decision::Approved,
        ),
        (|| ConsentOutcome::Denied, Decision::Denied),
        (|| ConsentOutcome::TimedOut, Decision::TimedOut),
        (
            || ConsentOutcome::Unavailable("no hello".into()),
            Decision::Unavailable,
        ),
    ] {
        let (a, shown) = approver(Ok(who()), answer);
        // 0.17's strict rule: /x/y, or X:\x\y with backslashes only.
        let path = format!(r"C:\safe\{}", "d".repeat(100));
        assert_eq!(a.approve(&req("proj_db", &path)), want);
        let text = shown.lock().unwrap().join("\n");
        assert!(
            text.contains(&format!("proj_db -> {path}")),
            "the whole subject is shown: {text}"
        );
        assert!(text.contains("lane 'lane-x'"), "{text}");
    }
}

#[test]
fn no_requester_no_prompt() {
    let (a, shown) = approver(Err("pid 1 is not in the process table".into()), || {
        ConsentOutcome::Approved
    });
    assert!(a.identity_error().is_some());
    assert_eq!(a.approve(&req("proj_db", "C:/safe/x")), Decision::Denied);
    assert!(
        shown.lock().unwrap().is_empty(),
        "the person is never asked on behalf of nobody"
    );
}

#[test]
fn through_the_face_an_unplaced_process_delivers_nothing() {
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
        SecretValue::from_string("CANARY-hello-2b7c".into()),
        BTreeMap::new(),
    )
    .unwrap();
    let safe = dir.path().join("safe");
    std::fs::create_dir(&safe).unwrap();
    let mk = |ap: Box<dyn PlacementApprover>| {
        let st = store.clone();
        Face::new(
            HostConfig::new(
                "lane-x",
                &["proj_"],
                vec![AllowRoot {
                    path: safe.clone(),
                    agent_unreadable: true,
                }],
                dir.path().join("l.json"),
                dir.path().join("r.jsonl"),
            )
            .unwrap(),
            Box::new(move || {
                let pw = SecretValue::from_string("pw".into());
                FileStore::open_with(&st, Unlock::Passphrase(&pw))
                    .map(|s| Box::new(s) as Box<dyn Store>)
            }),
            ap,
        )
    };
    let out = safe.join("k.secret");
    let args = json!({"placements":[{"name":"proj_db","path":out.to_string_lossy()}]});
    let (nobody, _) = approver(Err("self missing".into()), || ConsentOutcome::Approved);
    let v = mk(Box::new(nobody)).call("deliver", &args);
    assert_eq!(v["placements"][0]["status"], "denied");
    assert!(!out.exists());
    let (yes, _) = approver(Ok(who()), || ConsentOutcome::Approved);
    let v = mk(Box::new(yes)).call("deliver", &args);
    assert_eq!(v["placements"][0]["status"], "placed");
}
