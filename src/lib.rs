// SPDX-License-Identifier: MIT OR Apache-2.0
//! SecretAnt: one place, controlled by its owner, where secrets live.
//!
//! Row 1 of `ROADMAP.md`, in slices. Slices so far: [`SecretValue`]; the [`Store`] trait and the passphrase-wrapped [`FileStore`].

mod cloudflare;
mod deliver;
mod read;
mod store;
mod value;

pub use cloudflare::{CloudflareError, CloudflareWorker, MAX_BULK};
/// Cloudflare Worker delivery: plan, apply and verify.
pub mod cf {
    pub use crate::cloudflare::{Mapping, apply, plan, verify};
}
pub use deliver::{
    Action, DeliverError, Ledger, Outcome, Placement, State, Target, apply, plan, verify,
};
pub use read::{ReadConfig, ReadError, ReadUnlock, SecretReader};
pub use store::{EntryInfo, FileStore, KdfParams, Store, StoreError, Unlock};
pub use value::SecretValue;
