// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Secrets step: canaries (with a planted control), keep-by-default,
//! stale plan, atomic single write, generated values.

use secretant::secrets_step::{
    Encoding, SecretAction, SecretRequest, SecretsError, Source, apply_secrets, plan_secrets,
    probe_secrets, read_back_secrets,
};
use secretant::{FileStore, KdfParams, SecretValue, Store};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const FAST: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const CANARY: &str = "CANARY-typed-token-9f3a";

fn pass(s: &str) -> SecretValue {
    SecretValue::from_string(s.into())
}

fn store(dir: &tempfile::TempDir) -> (FileStore, PathBuf) {
    let path = dir.path().join("s.secretant");
    (
        FileStore::create_with_params(&path, &pass("pw"), FAST).unwrap(),
        path,
    )
}

fn given(name: &str, v: &str) -> SecretRequest {
    SecretRequest {
        name: name.into(),
        source: Source::Given(pass(v)),
        rotate: false,
    }
}

fn totp(name: &str) -> SecretRequest {
    SecretRequest {
        name: name.into(),
        source: Source::Generated {
            bytes: 32,
            encoding: Encoding::Base64,
        },
        rotate: false,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn a_generated_key_is_32_random_bytes_in_padded_base64_and_never_returned() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, _) = store(&dir);
    let plan = plan_secrets(probe_secrets(&s), vec![totp("TOTP_ENCRYPTION_KEY")]).unwrap();
    assert_eq!(plan.actions(), [("TOTP_ENCRYPTION_KEY", SecretAction::Add)]);
    let r = apply_secrets(&mut s, plan).unwrap();
    assert_eq!((r.added, r.new_versions, r.kept), (1, 0, 0));
    let v = s.get("TOTP_ENCRYPTION_KEY").unwrap();
    let text = std::str::from_utf8(v.expose()).unwrap().to_string();
    assert_eq!(text.len(), 44);
    assert!(text.ends_with('='));
    assert!(
        text.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    );
    // Not a constant: a second store draws a different value.
    let dir2 = tempfile::tempdir().unwrap();
    let (mut s2, _) = store(&dir2);
    let p2 = plan_secrets(probe_secrets(&s2), vec![totp("TOTP_ENCRYPTION_KEY")]).unwrap();
    apply_secrets(&mut s2, p2).unwrap();
    assert_ne!(v.expose(), s2.get("TOTP_ENCRYPTION_KEY").unwrap().expose());
    // Hex: 16 bytes is 32 lower-case digits.
    let hexreq = SecretRequest {
        name: "H".into(),
        source: Source::Generated {
            bytes: 16,
            encoding: Encoding::Hex,
        },
        rotate: false,
    };
    let p3 = plan_secrets(probe_secrets(&s), vec![hexreq]).unwrap();
    apply_secrets(&mut s, p3).unwrap();
    let h = s.get("H").unwrap();
    assert_eq!(h.len(), 32);
    assert!(
        h.expose()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(s.describe("H").unwrap().metadata["origin"], "generated");
}

#[test]
fn a_typed_value_appears_in_no_plan_report_error_or_the_store_file() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, path) = store(&dir);
    let plan = plan_secrets(
        probe_secrets(&s),
        vec![given("RESEND_API_KEY", CANARY), totp("TOTP_ENCRYPTION_KEY")],
    )
    .unwrap();
    let mut shown = format!("{plan:?}");
    let report = apply_secrets(&mut s, plan).unwrap();
    shown += &format!("{report:?}");
    let found = read_back_secrets(&s, &["RESEND_API_KEY", "TOTP_ENCRYPTION_KEY", "ABSENT"]);
    shown += &format!("{found:?}");
    let err = plan_secrets(probe_secrets(&s), vec![given("X", "")])
        .err()
        .unwrap();
    shown += &format!("{err:?} {err}");
    assert!(!shown.contains(CANARY));
    let generated = s.get("TOTP_ENCRYPTION_KEY").unwrap();
    assert!(!shown.contains(std::str::from_utf8(generated.expose()).unwrap()));
    // Control: the search finds a name, which is shown.
    assert!(shown.contains("RESEND_API_KEY"));
    let bytes = fs::read(&path).unwrap();
    assert!(!contains(&bytes, CANARY.as_bytes()));
    assert!(!contains(&bytes, generated.expose()));
    // Control: the same search finds text that is in the file.
    assert!(contains(&bytes, b"passphrase"));
    assert_eq!(found[0].version, Some(1));
    assert!(found[0].non_empty && found[1].non_empty);
    assert_eq!(found[2].version, None);
    assert!(!found[2].non_empty);
}

#[test]
fn a_rerun_keeps_what_is_there_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, path) = store(&dir);
    let first = plan_secrets(
        probe_secrets(&s),
        vec![given("A", "one"), totp("TOTP_ENCRYPTION_KEY")],
    )
    .unwrap();
    apply_secrets(&mut s, first).unwrap();
    let key = s.get("TOTP_ENCRYPTION_KEY").unwrap();
    let before = fs::read(&path).unwrap();
    let again = plan_secrets(
        probe_secrets(&s),
        vec![given("A", "two"), totp("TOTP_ENCRYPTION_KEY")],
    )
    .unwrap();
    assert_eq!(
        again.actions(),
        [
            ("A", SecretAction::Keep),
            ("TOTP_ENCRYPTION_KEY", SecretAction::Keep)
        ]
    );
    let r = apply_secrets(&mut s, again).unwrap();
    assert_eq!((r.added, r.new_versions, r.kept), (0, 0, 2));
    assert_eq!(before, fs::read(&path).unwrap(), "no-op wrote the file");
    assert_eq!(s.get("A").unwrap().expose(), b"one");
    assert_eq!(s.get("TOTP_ENCRYPTION_KEY").unwrap().expose(), key.expose());
}

#[test]
fn rotation_adds_a_version_and_deletes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, _) = store(&dir);
    let p = plan_secrets(probe_secrets(&s), vec![given("A", "one")]).unwrap();
    apply_secrets(&mut s, p).unwrap();
    let mut req = given("A", "two");
    req.rotate = true;
    let p = plan_secrets(probe_secrets(&s), vec![req]).unwrap();
    assert_eq!(p.actions(), [("A", SecretAction::AddVersion)]);
    let r = apply_secrets(&mut s, p).unwrap();
    assert_eq!(r.new_versions, 1);
    assert_eq!(s.describe("A").unwrap().latest, 2);
    assert_eq!(s.get_version("A", 1).unwrap().expose(), b"one");
    assert_eq!(s.get("A").unwrap().expose(), b"two");
}

#[test]
fn a_stale_plan_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, path) = store(&dir);
    let plan = plan_secrets(probe_secrets(&s), vec![given("A", "one")]).unwrap();
    // The store changes between plan and apply.
    s.put("B", pass("b"), BTreeMap::new()).unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        apply_secrets(&mut s, plan).err(),
        Some(SecretsError::StalePlan)
    );
    assert_eq!(before, fs::read(&path).unwrap());
    assert!(s.get("A").is_err());
}

#[test]
fn all_names_go_in_one_write_or_none_do() {
    let dir = tempfile::tempdir().unwrap();
    let (mut s, path) = store(&dir);
    // One write: the previous generation (.prev) holds the empty store, not a
    // half-way state with only some of the names.
    let plan = plan_secrets(
        probe_secrets(&s),
        vec![given("A", "a"), given("B", "b"), given("C", "c")],
    )
    .unwrap();
    apply_secrets(&mut s, plan).unwrap();
    let mut prev = path.clone().into_os_string();
    prev.push(".prev");
    let old = FileStore::open(PathBuf::from(prev), &pass("pw")).unwrap();
    assert!(old.list().is_empty());
    assert_eq!(
        FileStore::open(&path, &pass("pw")).unwrap().list(),
        ["A", "B", "C"]
    );
    // A bad name anywhere stops the whole request before anything is written.
    let before = fs::read(&path).unwrap();
    let err = plan_secrets(
        probe_secrets(&s),
        vec![given("D", "d"), given("bad\nname", "x")],
    );
    assert_eq!(err.err(), Some(SecretsError::BadName));
    assert_eq!(before, fs::read(&path).unwrap());
}

#[test]
fn empty_values_duplicates_and_zero_lengths_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (s, _) = store(&dir);
    let e = |reqs| plan_secrets(probe_secrets(&s), reqs).err();
    assert_eq!(e(vec![given("A", "")]), Some(SecretsError::EmptyValue));
    assert_eq!(
        e(vec![SecretRequest {
            name: "A".into(),
            source: Source::Generated {
                bytes: 0,
                encoding: Encoding::Hex
            },
            rotate: false
        }]),
        Some(SecretsError::EmptyValue)
    );
    assert_eq!(
        e(vec![given("A", "x"), given("A", "y")]),
        Some(SecretsError::DuplicateName)
    );
    assert_eq!(e(vec![given("", "x")]), Some(SecretsError::BadName));
}
