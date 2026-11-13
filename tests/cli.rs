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
            .arg("--passphrase-env")
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

#[test]
fn with_no_terminal_and_no_option_nothing_is_read_from_the_environment() {
    // Piped stdin is not a terminal. The passphrase variable is set, but it is
    // used only when --passphrase-env is given.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.json");
    let mut c = Command::new(env!("CARGO_BIN_EXE_secretant"));
    c.arg("--store")
        .arg(&store)
        .arg("init")
        .env("SECRETANT_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(PASS.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "init must refuse with no terminal"
    );
    assert!(!store.exists(), "nothing may be created");
    no_canary(&o);
    let err = text(&o.stderr);
    assert!(
        err.contains("--passphrase-stdin"),
        "the error must say what to do: {err}"
    );
}

#[test]
fn passphrase_from_stdin_is_still_available_when_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store.json");
    let run = |args: &[&str], stdin: &str| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_secretant"));
        c.arg("--store")
            .arg(&store)
            .arg("--passphrase-stdin")
            .args(args)
            .env_remove("SECRETANT_PASSPHRASE")
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
    };
    assert!(
        run(
            &["init"],
            &format!(
                "{PASS}
"
            )
        )
        .status
        .success()
    );
    // first line is the passphrase, the rest is the value
    assert!(
        run(
            &["put", NAME],
            &format!(
                "{PASS}
{VALUE}"
            )
        )
        .status
        .success()
    );
    let got = run(
        &["get", NAME],
        &format!(
            "{PASS}
"
        ),
    );
    assert_eq!(text(&got.stdout), VALUE);
}

// ---- row 7: backup, restore, doctor, export, import ----

const BUNDLE_PASS: &str = "CANARY-bundle-5d27e8b0";

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every encoding of `s` a careless writer might leave in a file.
fn encodings(s: &str) -> Vec<Vec<u8>> {
    let bare: String = s.chars().filter(|c| *c != '-').collect();
    let mut v = Vec::new();
    for t in [s.to_string(), bare, s.to_uppercase(), s.to_lowercase()] {
        v.push(t.clone().into_bytes());
        v.push(hex(t.as_bytes()).into_bytes());
        v.push(b64(t.as_bytes()).into_bytes());
        v.push(t.encode_utf16().flat_map(u16::to_le_bytes).collect());
    }
    v
}

fn holds(bytes: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn backup_is_ciphertext_holds_no_recovery_text_and_restores() {
    let r = Run::new();
    let init = r.cmd(&["init", "--recovery"], "");
    assert!(init.status.success());
    let recovery = text(&init.stdout).trim().to_string();
    assert_eq!(recovery.len(), 71, "64 hex digits in 8 groups");
    assert!(r.cmd(&["put", NAME], VALUE).status.success());

    let dest = r._dir.path().join("backup.json");
    let b = r.cmd(&["backup", dest.to_str().unwrap()], "");
    assert!(b.status.success());
    no_canary(&b);
    let bytes = std::fs::read(&dest).unwrap();

    // Negative control: the search does find text that is there.
    let mut planted = bytes.clone();
    planted.extend_from_slice(recovery.as_bytes());
    assert!(holds(&planted, recovery.as_bytes()));
    for secret in [recovery.as_str(), VALUE, PASS] {
        for e in encodings(secret) {
            assert!(!holds(&bytes, &e), "a secret is in the backup");
        }
    }
    // The backup is the ciphertext of the store, byte for byte.
    assert_eq!(bytes, std::fs::read(&r.store).unwrap());

    let t = r.cmd(&["restore-test", dest.to_str().unwrap()], "");
    assert!(t.status.success());
    assert!(text(&t.stdout).contains("1 entries, 1 versions"));
    no_canary(&t);

    // Restore into a fresh place, then read the value back.
    let other = Run::new();
    let rs = Command::new(env!("CARGO_BIN_EXE_secretant"))
        .arg("--store")
        .arg(&other.store)
        .arg("--passphrase-env")
        .args(["restore", dest.to_str().unwrap()])
        .env("SECRETANT_PASSPHRASE", PASS)
        .output()
        .unwrap();
    assert!(rs.status.success());
    assert_eq!(text(&other.cmd(&["get", NAME], "").stdout), VALUE);

    // Restoring over an existing store needs --replace and keeps .prev.
    let dest_s = dest.to_str().unwrap();
    let again = other.cmd(&["restore", dest_s], "");
    assert_eq!(again.status.code(), Some(1));
    no_canary(&again);
    let rep = other.cmd(&["restore", dest_s, "--replace"], "");
    assert!(rep.status.success());
    let mut prev = other.store.as_os_str().to_owned();
    prev.push(".prev");
    assert!(std::path::Path::new(&prev).exists());
}

#[test]
fn a_damaged_backup_fails_restore_test_and_restore_loudly() {
    let r = Run::new();
    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());
    let dest = r._dir.path().join("backup.json");
    assert!(
        r.cmd(&["backup", dest.to_str().unwrap()], "")
            .status
            .success()
    );
    let mut bytes = std::fs::read(&dest).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] = if bytes[mid] == b'0' { b'1' } else { b'0' };
    std::fs::write(&dest, &bytes).unwrap();

    let t = r.cmd(&["restore-test", dest.to_str().unwrap()], "");
    assert_eq!(t.status.code(), Some(1));
    no_canary(&t);
    let before = std::fs::read(&r.store).unwrap();
    let rs = r.cmd(&["restore", dest.to_str().unwrap(), "--replace"], "");
    assert_eq!(rs.status.code(), Some(1));
    // The bad backup did not replace the good store.
    assert_eq!(before, std::fs::read(&r.store).unwrap());
}

#[test]
fn doctor_reports_in_fixed_sentences_and_fails_on_a_missing_store() {
    let r = Run::new();
    let missing = r.cmd(&["doctor", "--header-only"], "");
    assert_eq!(missing.status.code(), Some(1));
    assert!(text(&missing.stdout).contains("FAIL"));

    assert!(r.cmd(&["init"], "").status.success());
    assert!(r.cmd(&["put", NAME], VALUE).status.success());
    let d = r.cmd(&["doctor"], "");
    assert!(d.status.success());
    let out = text(&d.stdout);
    assert!(
        out.contains("warn"),
        "one wrap and no recovery key are warned: {out}"
    );
    assert!(!out.contains(NAME), "no name in the report");
    assert!(
        !out.contains(&*r.store.to_string_lossy()),
        "no path in the report"
    );
    no_canary(&d);
}

#[test]
fn export_and_import_dry_run_apply_and_conflicts() {
    let a = Run::new();
    assert!(a.cmd(&["init"], "").status.success());
    assert!(a.cmd(&["put", NAME], VALUE).status.success());
    let bundle = a._dir.path().join("bundle.json");
    let bundle_s = bundle.to_str().unwrap();
    let ex = a.cmd(
        &["export", bundle_s, "--bundle-passphrase-stdin"],
        &format!("{BUNDLE_PASS}\n"),
    );
    assert!(ex.status.success());
    no_canary(&ex);
    let bytes = std::fs::read(&bundle).unwrap();
    for secret in [VALUE, BUNDLE_PASS, PASS] {
        for e in encodings(secret) {
            assert!(!holds(&bytes, &e), "a secret is in the bundle");
        }
    }

    let b = Run::new();
    assert!(b.cmd(&["init"], "").status.success());
    let imp = |args: &[&str]| {
        let mut v = vec!["import", bundle_s, "--bundle-passphrase-stdin"];
        v.extend_from_slice(args);
        b.cmd(&v, &format!("{BUNDLE_PASS}\n"))
    };

    // Dry run writes nothing.
    let before = std::fs::read(&b.store).unwrap();
    let dry = imp(&[]);
    assert!(dry.status.success());
    assert!(text(&dry.stdout).contains("new"));
    assert!(text(&dry.stdout).contains("dry run"));
    no_canary(&dry);
    assert_eq!(before, std::fs::read(&b.store).unwrap());
    assert_eq!(text(&b.cmd(&["list"], "").stdout).trim(), "");

    // A wrong bundle passphrase fails with a class only.
    let wrong = b.cmd(
        &["import", bundle_s, "--bundle-passphrase-stdin", "--apply"],
        "not-the-bundle-passphrase\n",
    );
    assert_eq!(wrong.status.code(), Some(1));
    no_canary(&wrong);

    let ap = imp(&["--apply"]);
    assert!(ap.status.success());
    assert!(text(&ap.stdout).contains("1 added"));
    assert_eq!(text(&b.cmd(&["get", NAME], "").stdout), VALUE);

    // The name is in both now: no choice means refused and nothing written.
    let snapshot = std::fs::read(&b.store).unwrap();
    let conflict = imp(&["--apply"]);
    assert_eq!(conflict.status.code(), Some(1));
    assert_eq!(snapshot, std::fs::read(&b.store).unwrap());
    let keep = imp(&["--apply", "--conflict", "keep"]);
    assert!(text(&keep.stdout).contains("1 kept"));
    let rep = imp(&["--apply", "--conflict", "replace"]);
    assert!(text(&rep.stdout).contains("1 replaced"));
    // Nothing deleted: the replaced value is a new version 2; version 1 stays.
    assert_eq!(
        text(&b.cmd(&["get", NAME, "--version", "2"], "").stdout),
        VALUE
    );
    assert_eq!(
        text(&b.cmd(&["get", NAME, "--version", "1"], "").stdout),
        VALUE
    );
}
