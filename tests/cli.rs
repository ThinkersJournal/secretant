// SPDX-License-Identifier: MIT OR Apache-2.0
//! Canary tests for the `secretant` command line. A canary value must come out
//! only where it is meant to: `get` stdout and the child's environment.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const VALUE: &str = "CANARY-value-7f3a91c2e5";
const PASS: &str = "CANARY-pass-2b8d40a6f1";
const NAME: &str = "CANARY_NAME_9c1e";

struct Run {
    store: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Run {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store.json");
        Run { store, _dir: dir }
    }

    fn cmd(&self, args: &[&str], stdin: &str) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_secretant"));
        c.arg("--store")
            .arg(&self.store)
            .args(args)
            .env("SECRETANT_PASSPHRASE", PASS)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn no_canary(o: &Output) {
    let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(!all.contains(VALUE), "the value leaked: {all}");
    assert!(!all.contains(PASS), "the passphrase leaked: {all}");
}

#[test]
fn put_list_get_rotate() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    let put = r.cmd(&["put", NAME], VALUE);
    assert!(put.status.success());
    no_canary(&put);

    let list = r.cmd(&["list"], "");
    assert!(list.status.success());
    assert_eq!(text(&list.stdout).trim(), NAME);
    no_canary(&list);

    let get = r.cmd(&["get", NAME], "");
    assert_eq!(text(&get.stdout), VALUE);

    // rotate writes version 2 and keeps version 1.
    let rot = r.cmd(&["rotate", NAME], "second\n");
    assert!(rot.status.success());
    assert_eq!(text(&rot.stdout).trim(), "version 2");
    assert_eq!(text(&r.cmd(&["get", NAME], "").stdout), "second");
    assert_eq!(
        text(&r.cmd(&["get", NAME, "--version", "1"], "").stdout),
        VALUE
    );

    // rotate of a name that does not exist is refused and writes nothing.
    let bad = r.cmd(&["rotate", "other"], "x");
    assert_eq!(bad.status.code(), Some(1));
    assert_eq!(text(&r.cmd(&["list"], "").stdout).trim(), NAME);
}

#[test]
fn a_value_is_never_an_argument() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    let o = r.cmd(&["put", NAME, VALUE], "");
    assert_eq!(o.status.code(), Some(2), "a value in argv must be refused");
    no_canary(&o);
    // and nothing was written
    assert!(text(&r.cmd(&["list"], "").stdout).trim().is_empty());
}

#[test]
fn errors_name_a_class_only() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());

    let missing = r.cmd(&["get", "CANARY_missing_name"], "");
    assert_eq!(missing.status.code(), Some(1));
    let e = text(&missing.stderr);
    assert!(
        !e.contains("CANARY_missing_name"),
        "an error echoed a name: {e}"
    );
    no_canary(&missing);

    // wrong passphrase through stdin
    let wrong = r.cmd(&["--passphrase-stdin", "get", NAME], "not-the-passphrase\n");
    assert_eq!(wrong.status.code(), Some(1));
    no_canary(&wrong);

    // init over an existing store is refused
    let again = r.cmd(&["init"], "");
    assert_eq!(again.status.code(), Some(1));
}

#[test]
fn recovery_key_opens_the_store() {
    let r = Run::new();
    let init = r.cmd(&["init", "--recovery"], "");
    assert!(init.status.success());
    let key = text(&init.stdout).trim().to_string();
    assert_eq!(key.matches('-').count(), 7, "recovery text shape");
    assert!(r.cmd(&["put", NAME], VALUE).status.success());
    let got = r.cmd(&["--recovery-stdin", "get", NAME], &format!("{key}\n"));
    assert_eq!(text(&got.stdout), VALUE);
}

fn print_env_command(var: &str) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), format!("echo [%{var}%]")]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '[%s]' \"${var}\""),
        ]
    }
}

#[test]
fn run_gives_the_child_the_value_and_not_the_passphrase() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());

    let mut args = vec!["run".to_string(), NAME.to_string(), "--".to_string()];
    args.extend(print_env_command(NAME));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = r.cmd(&refs, "");
    assert!(o.status.success(), "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains(VALUE),
        "the child did not get the value"
    );
    // the value is not in this process's own output besides what the child printed
    assert!(!text(&o.stderr).contains(VALUE));

    // the unlock passphrase must not reach the child
    let mut args = vec!["run".to_string(), NAME.to_string(), "--".to_string()];
    args.extend(print_env_command("SECRETANT_PASSPHRASE"));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = r.cmd(&refs, "");
    assert!(
        !text(&o.stdout).contains(PASS),
        "the passphrase reached the child"
    );
    assert!(
        text(&o.stdout).contains('['),
        "the child did not run (negative control)"
    );
}

#[test]
fn run_passes_the_childs_exit_code() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());
    let (prog, a, b) = if cfg!(windows) {
        ("cmd", "/C", "exit 7")
    } else {
        ("sh", "-c", "exit 7")
    };
    let o = r.cmd(&["run", NAME, "--", prog, a, b], "");
    assert_eq!(o.status.code(), Some(7));
}

#[test]
fn deliver_plan_apply_verify_never_shows_a_value() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());
    let dir = r._dir.path().to_path_buf();
    let out_file = dir.join("out.secret");
    let manifest = dir.join("m.json");
    let body = serde_json::json!({"placements": [
        {"name": NAME, "file": out_file},
        {"name": NAME, "env_file": dir.join("app.env"), "var": "DB_URL"}
    ]});
    std::fs::write(&manifest, body.to_string()).unwrap();
    let m = manifest.to_str().unwrap();

    let plan = r.cmd(&["deliver", "plan", m], "");
    assert!(plan.status.success());
    assert!(text(&plan.stdout).contains("create"));
    assert!(!out_file.exists(), "plan must write nothing");
    no_canary(&plan);

    let apply = r.cmd(&["deliver", "apply", m], "");
    assert!(apply.status.success(), "{}", text(&apply.stderr));
    no_canary(&apply);
    assert_eq!(std::fs::read(&out_file).unwrap(), VALUE.as_bytes());

    let ok = r.cmd(&["deliver", "verify", m], "");
    assert!(ok.status.success());
    assert!(text(&ok.stdout).contains("in-sync"));

    // a hand edit is reported as drift, exit 1, and the report holds no value
    std::fs::write(&out_file, b"hand edit").unwrap();
    let drift = r.cmd(&["deliver", "verify", m], "");
    assert_eq!(drift.status.code(), Some(1));
    assert!(text(&drift.stdout).contains("drifted"));
    no_canary(&drift);
    assert!(!text(&drift.stdout).contains("hand edit"));
}
