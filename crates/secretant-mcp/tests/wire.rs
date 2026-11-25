// SPDX-License-Identifier: MIT OR Apache-2.0
//! The no-value test at the rmcp layer (pm-ants condition): the real MCP server
//! is driven with raw JSON-RPC lines, well formed and malformed, and every byte
//! it writes back (and every log line) must be free of the canary in any form.
#![cfg(feature = "stdio")]

use secretant::{FileStore, KdfParams, SecretValue, Store, Unlock};
use secretant_mcp::serve::FaceServer;
use secretant_mcp::{AllowRoot, Decision, Face, HostConfig, PlacementApprover, PlacementRequest};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};

const CANARY: &str = "CANARY-wire-5c2e90ab17d4f386";
/// Text the CLIENT types into malformed calls. It is not a stored value.
const TYPED: &str = "TYPED-wire-0a1b2c3d4e5f";

struct Yes;
impl PlacementApprover for Yes {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        Decision::Approved
    }
}

fn forms() -> Vec<String> {
    let b = CANARY.as_bytes();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    vec![
        CANARY.to_string(),
        hex.clone(),
        hex.to_uppercase(),
        "5c2e90ab17d4f386".to_string(),
    ]
}

#[tokio::test]
async fn nothing_the_server_writes_names_a_value() {
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
        SecretValue::from_string(CANARY.into()),
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
    let st = store.clone();
    let face = Face::new(
        cfg,
        Box::new(move || {
            let pw = SecretValue::from_string("pw".into());
            FileStore::open_with(&st, Unlock::Passphrase(&pw))
                .map(|s| Box::new(s) as Box<dyn Store>)
        }),
        Box::new(Yes),
    );

    let (client, server) = duplex(1 << 16);
    tokio::spawn(async move {
        use rmcp::ServiceExt;
        if let Ok(svc) = FaceServer::new(face).serve(server).await {
            let _ = svc.waiting().await;
        }
    });
    let (r, mut w) = tokio::io::split(client);
    let mut r = BufReader::new(r);
    let mut heard = String::new();
    macro_rules! exchange {
        ($line:expr) => {{
            say($line, &mut w).await;
            let mut got = String::new();
            let _ = tokio::time::timeout(Duration::from_millis(1500), r.read_line(&mut got)).await;
            heard.push_str(&got);
            serde_json::from_str::<Value>(&got).unwrap_or(Value::Null)
        }};
    }

    let init = exchange!(
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}})
        .to_string()
    );
    assert!(init["result"].is_object());
    say(
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string(),
        &mut w,
    )
    .await;

    let list =
        exchange!(json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string());
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        names,
        ["list_names", "ledger_read", "verify_placement", "deliver"],
        "only these four tools exist"
    );

    let out = safe.join("db.secret");
    let call = |id: u32, name: &str, args: Value| {
        json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}}).to_string()
    };
    let ok = exchange!(call(
        3,
        "deliver",
        json!({"placements":[{"name":"proj_db","path":out.to_string_lossy()}]})
    ));
    assert_eq!(ok["result"]["isError"], false);
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        CANARY,
        "the canary was in play"
    );
    exchange!(call(4, "list_names", json!({})));
    exchange!(call(5, "get", json!({"name":"proj_db","note":TYPED})));
    exchange!(call(6, "deliver", json!({"placements": TYPED})));
    exchange!(call(
        7,
        "deliver",
        json!({"placements":[{"name":TYPED,"path":7}]})
    ));
    // Malformed at the protocol layer: arguments that name a value must not be echoed.
    exchange!(json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":{"x":TYPED},"arguments":TYPED}}).to_string());
    exchange!(json!({"jsonrpc":"2.0","id":9,"method":TYPED,"params":{"v":TYPED}}).to_string());
    exchange!(json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":TYPED}).to_string());
    exchange!(format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"{TYPED}"
    ));

    assert!(heard.len() > 200, "the server answered");
    assert_value_not_echoed(&heard);
}

/// The STORED value must never come back, in any form, on any path. Text the
/// client typed (`TYPED`) is not a stored value; rmcp itself repeats an unknown
/// method name in its "method not found" error, and that is the only place it
/// may appear (the shim cannot change rmcp's own protocol errors).
fn assert_value_not_echoed(heard: &str) {
    for f in forms() {
        assert!(!heard.contains(&f), "{f:?} came back over the wire");
    }
    for l in heard.lines().filter(|l| l.contains(TYPED)) {
        assert!(
            l.contains("-32601"),
            "client text echoed outside method-not-found: {l}"
        );
    }
}

async fn say(text: String, w: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>) {
    w.write_all(format!("{text}\n").as_bytes()).await.unwrap();
}
