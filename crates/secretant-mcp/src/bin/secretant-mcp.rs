// SPDX-License-Identifier: MIT OR Apache-2.0
//! `secretant-mcp --config <host.json>`: the host starts the face. The config
//! is a file the human owns (never a tool argument) naming the store, the
//! ledger, the record, the role, its name prefixes and the allow-listed
//! directories. The store is opened with the OS unlock: no passphrase is read
//! from an argument, the environment or the config.
//!
//! Built without feature `hello`, every `deliver` is refused (`denied`); list,
//! ledger and verify work. With it, each placement asks the person through
//! Windows Hello, and a process the OS table cannot place is denied.

use secretant::{FileStore, Store, Unlock};
use secretant_mcp::serve::FaceServer;
use secretant_mcp::{AllowRoot, Face, HostConfig, PlacementApprover};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    path: PathBuf,
    #[serde(default)]
    agent_unreadable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    role: String,
    prefixes: Vec<String>,
    store: PathBuf,
    ledger: PathBuf,
    record: PathBuf,
    roots: Vec<Root>,
}

/// Windows Hello when built with `hello`; otherwise every delivery is refused.
#[cfg(feature = "hello")]
fn approver() -> Box<dyn PlacementApprover> {
    Box::new(secretant_mcp::hello::platform())
}
#[cfg(not(feature = "hello"))]
fn approver() -> Box<dyn PlacementApprover> {
    Box::new(secretant_mcp::DenyAll)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [flag, path] = args.as_slice() else {
        eprintln!("usage: secretant-mcp --config <host.json>");
        return std::process::ExitCode::from(2);
    };
    if flag != "--config" {
        eprintln!("usage: secretant-mcp --config <host.json>");
        return std::process::ExitCode::from(2);
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("secretant-mcp: the config file could not be read");
        return std::process::ExitCode::from(1);
    };
    let Ok(host) = serde_json::from_str::<Host>(&text) else {
        eprintln!("secretant-mcp: the config file is not valid");
        return std::process::ExitCode::from(1);
    };
    let prefixes: Vec<&str> = host.prefixes.iter().map(String::as_str).collect();
    let roots = host
        .roots
        .into_iter()
        .map(|r| AllowRoot {
            path: r.path,
            agent_unreadable: r.agent_unreadable,
        })
        .collect();
    let Ok(cfg) = HostConfig::new(&host.role, &prefixes, roots, host.ledger, host.record) else {
        eprintln!("secretant-mcp: a role and at least one name prefix are required");
        return std::process::ExitCode::from(1);
    };
    let store = host.store;
    // Fail at start, not at the first call, if the OS unlock cannot open it.
    if FileStore::open_with(&store, Unlock::Os).is_err() {
        eprintln!("secretant-mcp: the store could not be opened with the OS unlock");
        return std::process::ExitCode::from(1);
    }
    let face = Face::new(
        cfg,
        Box::new(move || {
            FileStore::open_with(&store, Unlock::Os).map(|s| Box::new(s) as Box<dyn Store>)
        }),
        approver(),
    );
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return std::process::ExitCode::from(1),
    };
    match rt.block_on(FaceServer::new(face).run_stdio()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("secretant-mcp: {e}");
            std::process::ExitCode::from(1)
        }
    }
}
