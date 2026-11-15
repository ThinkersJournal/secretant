// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Place step for files: canaries, no-op writes nothing, stale plan.

use secretant::place_step::{PlaceError, apply_place, plan_place, probe_place, read_back_place};
use secretant::{
    Action, DeliverError, FileStore, KdfParams, Ledger, Placement, SecretValue, State, Store,
    Target,
};
use std::collections::BTreeMap;
use std::fs;

const FAST: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const CANARY: &str = "CANARY-placed-value-7d21";

struct Rig {
    dir: tempfile::TempDir,
    store: FileStore,
    ledger: Ledger,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let mut store = FileStore::create_with_params(
        dir.path().join("s.secretant"),
        &SecretValue::from_string("pw".into()),
        FAST,
    )
    .unwrap();
    store
        .put(
            "A",
            SecretValue::from_string(CANARY.into()),
            BTreeMap::new(),
        )
        .unwrap();
    store
        .put(
            "B",
            SecretValue::from_string("b-one".into()),
            BTreeMap::new(),
        )
        .unwrap();
    let ledger = Ledger::open(dir.path().join("ledger.json")).unwrap();
    Rig { dir, store, ledger }
}

fn placements(dir: &std::path::Path) -> Vec<Placement> {
    vec![
        Placement {
            name: "A".into(),
            target: Target::File(dir.join("a.txt")),
        },
        Placement {
            name: "B".into(),
            target: Target::EnvFile {
                path: dir.join("app.env"),
                var: "B_VAR".into(),
            },
        },
    ]
}

#[test]
fn plan_apply_and_read_back_place_every_value_and_show_none() {
    let mut r = rig();
    let ps = placements(r.dir.path());
    let plan = plan_place(&r.store, &r.ledger, ps.clone());
    assert_eq!(plan.actions(), [(0, Action::Create), (1, Action::Create)]);
    let mut shown = format!("{plan:?} {:?}", probe_place(&r.store, &r.ledger, &ps));
    let done = apply_place(&r.store, &mut r.ledger, &plan).unwrap();
    shown += &format!("{done:?}");
    assert_eq!((done.placed, done.unchanged, done.failed.len()), (2, 0, 0));
    assert_eq!(
        fs::read_to_string(r.dir.path().join("a.txt")).unwrap(),
        CANARY
    );
    assert!(
        fs::read_to_string(r.dir.path().join("app.env"))
            .unwrap()
            .contains("B_VAR=b-one")
    );
    let back = read_back_place(&r.store, &r.ledger, &ps);
    shown += &format!("{back:?}");
    assert!(back.iter().all(|(_, s)| *s == State::InSync));
    assert!(!shown.contains(CANARY) && !shown.contains("b-one"));
    // Control: the search finds what is shown (a variable name).
    assert!(shown.contains("B_VAR"));
}

#[test]
fn a_rerun_writes_nothing_and_a_new_version_updates_only_what_changed() {
    let mut r = rig();
    let ps = placements(r.dir.path());
    let plan = plan_place(&r.store, &r.ledger, ps.clone());
    apply_place(&r.store, &mut r.ledger, &plan).unwrap();
    let again = plan_place(&r.store, &r.ledger, ps.clone());
    assert!(again.is_noop());
    // Make the file's modification observable: tamper-free check by removing
    // read-only nothing; instead a no-op must not rewrite, so a changed mtime
    // or content would show. Compare bytes and report counts.
    let before = fs::read(r.dir.path().join("a.txt")).unwrap();
    let done = apply_place(&r.store, &mut r.ledger, &again).unwrap();
    assert_eq!((done.placed, done.unchanged), (0, 2));
    assert_eq!(before, fs::read(r.dir.path().join("a.txt")).unwrap());
    // B gets a new version: only B is rewritten.
    r.store
        .put(
            "B",
            SecretValue::from_string("b-two".into()),
            BTreeMap::new(),
        )
        .unwrap();
    let plan = plan_place(&r.store, &r.ledger, ps.clone());
    assert_eq!(
        plan.actions(),
        [(0, Action::Unchanged), (1, Action::Update)]
    );
    let done = apply_place(&r.store, &mut r.ledger, &plan).unwrap();
    assert_eq!((done.placed, done.unchanged), (1, 1));
    assert!(
        fs::read_to_string(r.dir.path().join("app.env"))
            .unwrap()
            .contains("B_VAR=b-two")
    );
}

#[test]
fn a_target_changed_after_the_plan_is_refused_and_nothing_is_written() {
    let mut r = rig();
    let ps = placements(r.dir.path());
    let plan = plan_place(&r.store, &r.ledger, ps);
    // Someone creates a.txt by hand between plan and apply.
    fs::write(r.dir.path().join("a.txt"), "by hand").unwrap();
    assert_eq!(
        apply_place(&r.store, &mut r.ledger, &plan).err(),
        Some(PlaceError::StalePlan)
    );
    assert_eq!(
        fs::read_to_string(r.dir.path().join("a.txt")).unwrap(),
        "by hand"
    );
    assert!(!r.dir.path().join("app.env").exists());
}

#[test]
fn one_failing_placement_leaves_its_target_alone_and_the_others_go_on() {
    let mut r = rig();
    let mut ps = placements(r.dir.path());
    ps.push(Placement {
        name: "MISSING".into(),
        target: Target::File(r.dir.path().join("m.txt")),
    });
    let plan = plan_place(&r.store, &r.ledger, ps);
    let done = apply_place(&r.store, &mut r.ledger, &plan).unwrap();
    assert_eq!(done.placed, 2);
    assert_eq!(done.failed.len(), 1);
    assert_eq!(done.failed[0].0, 2);
    assert!(matches!(done.failed[0].1, DeliverError::Store(_)));
    assert!(!r.dir.path().join("m.txt").exists());
}
