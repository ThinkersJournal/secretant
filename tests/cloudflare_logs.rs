// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the HTTP client (`ureq`) logs and what our errors say: the API token
//! and the secret values must appear in neither, at the most verbose log level.
//! This file is its own test process because a logger is process-wide.

use secretant::cf;
use secretant::{CloudflareWorker, FileStore, KdfParams, Ledger, SecretValue, Store};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;

const TOKEN: &str = "CANARYtoken-LOGTEST-77aa31c9";
const VALUE: &str = "CANARY-value-LOGTEST-0e6f5d";

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        LINES.lock().unwrap().push(format!("{}", r.args()));
    }
    fn flush(&self) {}
}

/// A server that answers every request with `status` and a body that echoes the
/// token and the value, the worst case for a client that repeats response text.
fn echo_server(status: u16) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/client/v4", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let mut buf = [0u8; 8192];
            let mut got = Vec::new();
            loop {
                let n = c.read(&mut buf).unwrap_or(0);
                got.extend_from_slice(&buf[..n]);
                if n == 0 || got.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = format!(r#"{{"success":false,"errors":[{{"message":"{TOKEN} {VALUE}"}}]}}"#);
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = c.write_all(reply.as_bytes());
        }
    });
    base
}

#[test]
fn neither_the_log_nor_any_error_holds_the_token_or_a_value() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let dir = tempfile::tempdir().unwrap();
    let pw = SecretValue::from_string("pw".into());
    let mut store = FileStore::create_with_params(
        dir.path().join("s.secretant"),
        &pw,
        KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        },
    )
    .unwrap();
    for (n, v) in [("cf_token", TOKEN), ("k", VALUE)] {
        store
            .put(n, SecretValue::from_string(v.into()), BTreeMap::new())
            .unwrap();
    }
    let maps = vec![("k".to_string(), "K".to_string())];
    let mut ledger = Ledger::open(dir.path().join("l.json")).unwrap();

    let mut errors = Vec::new();
    for status in [401u16, 403, 404, 429, 500] {
        let w = CloudflareWorker::new("a", "s").with_base_url(echo_server(status));
        let e = cf::apply(&store, &mut ledger, &w, "cf_token", &maps).unwrap_err();
        errors.push(format!("{e} | {e:?}"));
    }
    // a refused connection
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}/client/v4", dead.local_addr().unwrap());
    drop(dead);
    let w = CloudflareWorker::new("a", "s").with_base_url(base);
    let e = cf::apply(&store, &mut ledger, &w, "cf_token", &maps).unwrap_err();
    errors.push(format!("{e} | {e:?}"));

    // Negative control: the capture sees a line logged at trace level, so an
    // empty capture below means the client logged nothing, not that we heard nothing.
    log::trace!("control line {}", "CONTROL-MARK");
    let logged = LINES.lock().unwrap().join("\n");
    assert!(
        logged.contains("CONTROL-MARK"),
        "the logger saw nothing; this test would prove nothing"
    );
    for text in errors.iter().map(String::as_str).chain([logged.as_str()]) {
        assert!(!text.contains(TOKEN), "the token leaked: {text}");
        assert!(!text.contains(VALUE), "a value leaked: {text}");
        assert!(!text.contains("LOGTEST"), "a canary leaked: {text}");
    }
}
