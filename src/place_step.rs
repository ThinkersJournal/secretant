// SPDX-License-Identifier: MIT OR Apache-2.0
//! The installer's Place step for files and environment files (ROADMAP row 8b,
//! second half; design in `docs/INSTALLER-STEPS.md` 4.3).
//!
//! A thin step over [`crate::deliver`]: the same four calls as the other steps
//! (`probe`, `plan`, `apply`, `read_back`), plus the fingerprint that makes
//! `apply` refuse a plan whose situation has changed. It never asks, prints or
//! logs, and carries names, indexes, versions and classes only: never a value.
//! Placing to a Cloudflare Worker is not in this step yet.

use crate::deliver::{self, Action, DeliverError, Ledger, Placement, State};
use crate::store::Store;
use std::fmt;

/// Why the step could not go on. A class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaceError {
    /// A target or the store changed since the plan was made: plan again.
    StalePlan,
}

impl fmt::Display for PlaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the targets changed since the plan was made: plan again")
    }
}

impl std::error::Error for PlaceError {}

/// What each placement's target holds right now. Names no value.
pub fn probe_place(
    store: &dyn Store,
    ledger: &Ledger,
    placements: &[Placement],
) -> Vec<(usize, State)> {
    deliver::verify(store, ledger, placements)
}

/// A plan: what `apply` will do for each placement, and the probe it was made
/// from (the fingerprint `apply` checks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacePlan {
    placements: Vec<Placement>,
    probe: Vec<(usize, State)>,
    actions: Vec<(usize, Action)>,
}

impl PlacePlan {
    /// What will be done for each placement, by index.
    pub fn actions(&self) -> &[(usize, Action)] {
        &self.actions
    }

    /// Nothing to do: `apply` would write nothing.
    pub fn is_noop(&self) -> bool {
        self.actions.iter().all(|(_, a)| *a == Action::Unchanged)
    }
}

/// Turn the placements into a plan. Pure: reads, writes nothing.
pub fn plan_place(store: &dyn Store, ledger: &Ledger, placements: Vec<Placement>) -> PlacePlan {
    let probe = probe_place(store, ledger, &placements);
    let actions = deliver::plan(store, ledger, &placements);
    PlacePlan {
        placements,
        probe,
        actions,
    }
}

/// What `apply` did. Counts, and the failures by index with their class.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlaceApplied {
    /// Targets written.
    pub placed: u32,
    /// Targets already holding the latest value, left alone.
    pub unchanged: u32,
    /// Placements that failed: the index and why. Each such target is as it was.
    pub failed: Vec<(usize, DeliverError)>,
}

/// Do exactly the plan, if the targets are still as they were when it was
/// made. A placement that needs nothing is not written (its file is not
/// touched); one that fails leaves its target as it was and the others go on.
pub fn apply_place(
    store: &dyn Store,
    ledger: &mut Ledger,
    plan: &PlacePlan,
) -> Result<PlaceApplied, PlaceError> {
    if probe_place(store, ledger, &plan.placements) != plan.probe {
        return Err(PlaceError::StalePlan);
    }
    let mut report = PlaceApplied::default();
    let mut todo = Vec::new();
    let mut index_of = Vec::new();
    for (i, action) in &plan.actions {
        if *action == Action::Unchanged {
            report.unchanged += 1;
        } else {
            todo.push(plan.placements[*i].clone());
            index_of.push(*i);
        }
    }
    for o in deliver::apply(store, ledger, &todo) {
        match o.result {
            Ok(_) => report.placed += 1,
            Err(e) => report.failed.push((index_of[o.index], e)),
        }
    }
    Ok(report)
}

/// Prove the result by reading it back: one state per placement. The step went
/// well when every state is [`State::InSync`].
pub fn read_back_place(
    store: &dyn Store,
    ledger: &Ledger,
    placements: &[Placement],
) -> Vec<(usize, State)> {
    deliver::verify(store, ledger, placements)
}
