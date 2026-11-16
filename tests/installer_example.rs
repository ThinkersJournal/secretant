// SPDX-License-Identifier: MIT OR Apache-2.0
//! The worked example of `docs/INSTALLER-EXAMPLE.md`, run: a fresh install from
//! nothing to values placed in an env file, then the same install again (which
//! must change nothing). The installer owns all asking and showing; the
//! library returns data. The docs and the plain-words text are checked here so
//! they cannot drift from the code.

use secretant::installer::{
    PLAIN_WORDS, StoreApplied, apply_store, confirm_recovery, plain_words, plan_store, probe_store,
    read_back_store,
};
use secretant::place_step::{apply_place, plan_place, read_back_place};
use secretant::secrets_step::{
    Encoding, SecretRequest, Source, apply_secrets, plan_secrets, probe_secrets, read_back_secrets,
};
use secretant::{FileStore, Ledger, Placement, SecretValue, State, Target, Unlock};
use std::fs;

const PASS: &str = "CANARY-example-pass-3e90";
const TOKEN: &str = "CANARY-example-token-84b1";

fn sv(s: &str) -> SecretValue {
    SecretValue::from_string(s.to_string())
}

/// The whole install, as the installer's step driver would run it.
fn install(dir: &std::path::Path) -> (String, Option<String>) {
    let path = dir.join("store.json");
    let mut shown = String::new();
    let mut key_shown = None;

    // 1. Store step: probe, plan, apply; show the key; confirm; read back.
    let plan = plan_store(&path, probe_store(&path), false);
    shown += &format!("{plan:?}");
    if let StoreApplied::Pending {
        store,
        recovery_key,
    } = apply_store(&plan, &sv(PASS)).unwrap()
    {
        // The installer shows the key (plain words first) and takes it typed back.
        let typed =
            SecretValue::from_string(String::from_utf8(recovery_key.expose().to_vec()).unwrap());
        key_shown = Some(String::from_utf8(typed.expose().to_vec()).unwrap());
        confirm_recovery(&store, &typed).unwrap();
    }
    let report = read_back_store(&path, Unlock::Passphrase(&sv(PASS))).unwrap();
    shown += &format!("{report:?}");

    // 2. Secrets step: the typed-in token and a generated key.
    let mut store = FileStore::open_with(&path, Unlock::Passphrase(&sv(PASS))).unwrap();
    let plan = plan_secrets(
        probe_secrets(&store),
        vec![
            SecretRequest {
                name: "cf_token".into(),
                source: Source::Given(sv(TOKEN)),
                rotate: false,
            },
            SecretRequest {
                name: "totp_key".into(),
                source: Source::Generated {
                    bytes: 32,
                    encoding: Encoding::Base64,
                },
                rotate: false,
            },
        ],
    )
    .unwrap();
    shown += &format!("{plan:?}");
    let done = apply_secrets(&mut store, plan).unwrap();
    shown += &format!("{done:?}");
    shown += &format!("{:?}", read_back_secrets(&store, &["cf_token", "totp_key"]));

    // 3. Place step: the generated key into an env file.
    let mut ledger = Ledger::open(dir.join("ledger.json")).unwrap();
    let placements = vec![Placement {
        name: "totp_key".into(),
        target: Target::EnvFile {
            path: dir.join("app.env"),
            var: "TOTP_ENCRYPTION_KEY".into(),
        },
    }];
    let plan = plan_place(&store, &ledger, placements.clone());
    shown += &format!("{plan:?}");
    let done = apply_place(&store, &mut ledger, &plan).unwrap();
    shown += &format!("{done:?}");
    let back = read_back_place(&store, &ledger, &placements);
    assert!(back.iter().all(|(_, s)| *s == State::InSync));
    shown += &format!("{back:?}");
    (shown, key_shown)
}

#[test]
fn the_worked_example_installs_from_nothing_and_a_second_run_changes_nothing() {
    let d = tempfile::tempdir().unwrap();
    let (shown, key) = install(d.path());
    let key = key.expect("the first run creates a store and returns a key");

    // The value is in the env file, and in nothing the steps showed.
    let env = fs::read_to_string(d.path().join("app.env")).unwrap();
    assert!(env.contains("TOTP_ENCRYPTION_KEY="));
    let value = env.split_once('=').unwrap().1.trim().to_string();
    assert!(!value.is_empty());
    for secret in [PASS, TOKEN, key.as_str(), value.as_str()] {
        assert!(!shown.contains(secret), "a secret was shown");
    }
    // Control: the search finds what is shown (a variable name).
    assert!(shown.contains("TOTP_ENCRYPTION_KEY") || shown.contains("totp_key"));

    // Second run: the store exists, nothing is created, no file changes.
    let files = ["store.json", "ledger.json", "app.env"];
    let before: Vec<_> = files
        .iter()
        .map(|f| fs::read(d.path().join(f)).unwrap())
        .collect();
    let (_, key2) = install(d.path());
    assert!(key2.is_none(), "a second run must not create another store");
    let after: Vec<_> = files
        .iter()
        .map(|f| fs::read(d.path().join(f)).unwrap())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn the_plain_words_are_design_8_2_word_for_word() {
    let design = include_str!("../docs/DESIGN.md").replace("\r\n", "\n");
    let quoted = plain_words("[Windows/your keychain]");
    assert!(
        design.contains(&format!("\"{quoted}\"")),
        "docs/DESIGN.md 8.2 and PLAIN_WORDS differ"
    );
    assert!(PLAIN_WORDS.contains("{protection}"));
    assert!(!plain_words("Windows").contains('{'));
}

#[test]
fn the_example_document_names_every_call_the_example_makes() {
    let doc = include_str!("../docs/INSTALLER-EXAMPLE.md");
    for call in [
        "probe_store",
        "plan_store",
        "apply_store",
        "confirm_recovery",
        "read_back_store",
        "probe_secrets",
        "plan_secrets",
        "apply_secrets",
        "read_back_secrets",
        "plan_place",
        "apply_place",
        "read_back_place",
        "plain_words",
    ] {
        assert!(
            doc.contains(call),
            "the example document does not mention {call}"
        );
    }
}
