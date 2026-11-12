// SPDX-License-Identifier: MIT OR Apache-2.0
//! SecretAnt: one place, controlled by its owner, where secrets live.
//!
//! Row 1 of `ROADMAP.md`, in slices. Slices so far: [`SecretValue`]; the [`Store`] trait and the passphrase-wrapped [`FileStore`].

mod read;
mod store;
mod value;

pub use read::{ReadConfig, ReadError, ReadUnlock, SecretReader};
pub use store::{EntryInfo, FileStore, KdfParams, Store, StoreError, Unlock};
pub use value::SecretValue;
