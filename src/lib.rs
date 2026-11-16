// SPDX-License-Identifier: MIT OR Apache-2.0
#![doc = include_str!("../README.md")]

#[cfg(feature = "cloudflare")]
mod cloudflare;
mod deliver;
/// The installer step library (ROADMAP row 8).
pub mod installer;
mod maintain;
/// The installer's Place step for files and environment files (ROADMAP row 8b).
pub mod place_step;
mod read;
/// The installer's Secrets step (ROADMAP row 8b).
pub mod secrets_step;
mod store;
mod value;

#[cfg(feature = "cloudflare")]
pub use cloudflare::{CloudflareError, CloudflareWorker, MAX_BULK};
/// Cloudflare Worker delivery: plan, apply and verify. Needs the `cloudflare` feature.
#[cfg(feature = "cloudflare")]
pub mod cf {
    pub use crate::cloudflare::{Mapping, apply, plan, verify};
}
pub use deliver::{
    Action, DeliverError, Ledger, Outcome, Placement, State, Target, apply, plan, verify,
};
pub use maintain::{BackupSummary, Check, Finding, Level, backup, check_backup, doctor, restore};
pub use read::{ReadConfig, ReadError, ReadUnlock, SecretReader};
pub use store::{
    EntryInfo, FileStore, ImportConflict, ImportItem, ImportReport, Inspection, KdfParams, Store,
    StoreError, Unlock,
};
pub use value::SecretValue;
