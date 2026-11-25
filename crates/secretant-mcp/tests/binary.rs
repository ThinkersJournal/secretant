// SPDX-License-Identifier: MIT OR Apache-2.0
//! The host binary: bad invocations fail closed, and a real stdio session lists
//! only the four tools and answers `list_names`, with no value on the wire.
#![cfg(feature = "stdio")]

use secretant::{FileStore, KdfParams, SecretValue, Store};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_secretant-mcp");
const CANARY: &str = "CANARY-bin-8d0f4a2b6c19";

#[test]
fn bad_invocations_fail_closed() {
    assert_eq!(Command::new(BIN).status().unwrap().code(), Some(2));
    assert_eq!(
        Command::new(BIN)
            .args(["--passphrase", "x"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
    let d = tempfile::tempdir().unwrap();
    let cfg = d.path().join("h.json");
    // An unknown field (say a passphrase) is refused, not ignored.
    std::fs::write(&cfg, json!({"role":"r","prefixes":["p_"],"store":"s","ledger":"l","record":"r","roots":[],"passphrase":"x"}).to_string()).unwrap();
    assert_eq!(
        Command::new(BIN)
            .arg("--config")
            .arg(&cfg)
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
    // No prefixes: no scope, no server.
    std::fs::write(
        &cfg,
        json!({"role":"r","prefixes":[],"store":"s","ledger":"l","record":"r","roots":[]})
            .to_string(),
    )
    .unwrap();
    assert_eq!(
        Command::new(BIN)
            .arg("--config")
            .arg(&cfg)
            .status()
            .unwrap()
            .code(),
        Some(1)
    );
}

#[cfg(windows)]
#[test]
fn a_real_session_over_stdio() {
    let d = tempfile::tempdir().unwrap();
    let store = d.path().join("s.secretant");
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
    s.add_os_wrap().unwrap();
    s.put(
        "proj_db",
        SecretValue::from_string(CANARY.into()),
        BTreeMap::new(),
    )
    .unwrap();
    s.put(
        "zzz_hidden",
        SecretValue::from_string(CANARY.into()),
        BTreeMap::new(),
    )
    .unwrap();
    let cfg = d.path().join("h.json");
    std::fs::write(
        &cfg,
        json!({"role":"r","prefixes":["proj_"],"store":store,"ledger":d.path().join("l.json"),
        "record":d.path().join("rec.jsonl"),"roots":[]})
        .to_string(),
    )
    .unwrap();
    let mut child = Command::new(BIN)
        .arg("--config")
        .arg(&cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let mut heard = String::new();
    let mut ask = |v: serde_json::Value, expect_reply: bool| {
        writeln!(stdin, "{v}").unwrap();
        if expect_reply {
            let mut l = String::new();
            out.read_line(&mut l).unwrap();
            heard.push_str(&l);
            l
        } else {
            String::new()
        }
    };
    ask(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
        true,
    );
    ask(
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        false,
    );
    let list = ask(
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_names","arguments":{}}}),
        true,
    );
    assert!(
        list.contains("proj_db") && !list.contains("zzz_hidden"),
        "{list}"
    );
    let del = ask(
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"deliver","arguments":{"placements":[{"name":"proj_db","path":"C:/nowhere/x"}]}}}),
        true,
    );
    assert!(del.contains("isError"), "{del}");
    assert!(!heard.contains(CANARY));
    drop(stdin);
    let _ = child.wait();
}
