// SPDX-License-Identifier: MIT OR Apache-2.0
//! The installer's Secrets step (ROADMAP row 8b; design in `docs/INSTALLER-STEPS.md` 4.2).
//!
//! `probe`, `plan`, `apply`, `read_back`. The step puts a product's secrets into
//! the person's store: a value the caller hands over (**given**) or a random one
//! the library draws (**generated**, never returned). It never asks, prints or
//! logs. Plans, reports and errors carry names, versions and classes, never a
//! value.
//!
//! A re-run changes nothing: a name already in the store is kept unless the
//! caller asks to rotate it, and all new versions go in with one atomic write.

use crate::store::{FileStore, Store, StoreError};
use crate::value::SecretValue;
use std::collections::BTreeMap;
use std::fmt;

/// How a generated value is written as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Standard base64 with `=` padding (what `TOTP_ENCRYPTION_KEY` takes).
    Base64,
    /// Lower-case hexadecimal.
    Hex,
}

/// Where a value comes from.
pub enum Source {
    /// The caller holds it (for example a token the person typed).
    Given(SecretValue),
    /// The library draws `bytes` random bytes and writes them in `encoding`.
    Generated {
        /// How many random bytes to draw (at least 1).
        bytes: usize,
        /// How to write them.
        encoding: Encoding,
    },
}

/// One name the step is asked to put in.
pub struct SecretRequest {
    /// The entry name.
    pub name: String,
    /// Where its value comes from.
    pub source: Source,
    /// Add a new version even if the name exists. Default `false`: keep it.
    pub rotate: bool,
}

/// What the step will do for one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAction {
    /// The name is not in the store: add it.
    Add,
    /// The name is there and no rotation was asked: leave it alone.
    Keep,
    /// The name is there and a rotation was asked: add a new version.
    AddVersion,
}

/// Why the step could not go on. A class only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsError {
    /// The store changed since the plan was made: plan again.
    StalePlan,
    /// A given value was empty, or a generated length was zero.
    EmptyValue,
    /// The same name was asked for twice.
    DuplicateName,
    /// A name is empty or has a control character.
    BadName,
    /// The store could not be written; it is as it was.
    Io,
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SecretsError::StalePlan => "the store changed since the plan was made: plan again",
            SecretsError::EmptyValue => "a secret value is empty",
            SecretsError::DuplicateName => "the same name was asked for twice",
            SecretsError::BadName => "a name is empty or has a control character",
            SecretsError::Io => "the store could not be written; it is as it was",
        })
    }
}

impl std::error::Error for SecretsError {}

impl From<StoreError> for SecretsError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::BadName => SecretsError::BadName,
            _ => SecretsError::Io,
        }
    }
}

/// What is in the store right now: each name and its latest version. Names
/// only; this is also the fingerprint a plan is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretsProbe {
    latest: BTreeMap<String, u32>,
}

impl SecretsProbe {
    /// The latest version of `name`, if the store has it.
    pub fn version(&self, name: &str) -> Option<u32> {
        self.latest.get(name).copied()
    }
}

/// Look at the (already unlocked) store.
pub fn probe_secrets(store: &FileStore) -> SecretsProbe {
    let latest = store
        .list()
        .into_iter()
        .filter_map(|n| store.describe(&n).ok().map(|i| (n, i.latest)))
        .collect();
    SecretsProbe { latest }
}

/// A plan: per name, what will happen, and the probe it was made from.
/// It holds the requested values until `apply`; they are never shown.
pub struct SecretsPlan {
    probe: SecretsProbe,
    items: Vec<(SecretRequest, SecretAction)>,
}

impl SecretsPlan {
    /// Each name and what will be done with it, in request order.
    pub fn actions(&self) -> Vec<(&str, SecretAction)> {
        self.items
            .iter()
            .map(|(r, a)| (r.name.as_str(), *a))
            .collect()
    }
}

impl fmt::Debug for SecretsPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsPlan")
            .field("actions", &self.actions())
            .finish()
    }
}

/// Turn a probe and the requests into a plan. Pure: writes nothing.
pub fn plan_secrets(
    probe: SecretsProbe,
    requests: Vec<SecretRequest>,
) -> Result<SecretsPlan, SecretsError> {
    let mut seen = std::collections::BTreeSet::new();
    let mut items = Vec::with_capacity(requests.len());
    for r in requests {
        if r.name.is_empty() || r.name.chars().any(|c| c.is_control()) {
            return Err(SecretsError::BadName);
        }
        if !seen.insert(r.name.clone()) {
            return Err(SecretsError::DuplicateName);
        }
        match &r.source {
            Source::Given(v) if v.is_empty() => return Err(SecretsError::EmptyValue),
            Source::Generated { bytes: 0, .. } => return Err(SecretsError::EmptyValue),
            _ => {}
        }
        let action = match (probe.version(&r.name), r.rotate) {
            (None, _) => SecretAction::Add,
            (Some(_), false) => SecretAction::Keep,
            (Some(_), true) => SecretAction::AddVersion,
        };
        items.push((r, action));
    }
    Ok(SecretsPlan { probe, items })
}

/// What `apply` did. Counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecretsApplied {
    /// Names added.
    pub added: u32,
    /// Names given a new version.
    pub new_versions: u32,
    /// Names left as they were.
    pub kept: u32,
}

/// Do exactly the plan, if the store is still as it was when planned. All new
/// versions are written in one atomic write; if there is nothing to add, nothing
/// is written (the file is byte-for-byte unchanged). On failure the store is as
/// it was.
pub fn apply_secrets(
    store: &mut FileStore,
    plan: SecretsPlan,
) -> Result<SecretsApplied, SecretsError> {
    if probe_secrets(store) != plan.probe {
        return Err(SecretsError::StalePlan);
    }
    let mut report = SecretsApplied::default();
    let mut batch = Vec::new();
    for (req, action) in plan.items {
        match action {
            SecretAction::Keep => report.kept += 1,
            SecretAction::Add | SecretAction::AddVersion => {
                let (value, origin) = match req.source {
                    Source::Given(v) => (v, "given"),
                    Source::Generated { bytes, encoding } => {
                        (generate(bytes, encoding)?, "generated")
                    }
                };
                if action == SecretAction::Add {
                    report.added += 1;
                } else {
                    report.new_versions += 1;
                }
                let mut meta = BTreeMap::new();
                meta.insert("origin".to_string(), origin.to_string());
                batch.push((req.name, value, meta));
            }
        }
    }
    if !batch.is_empty() {
        store.put_many(batch)?;
    }
    Ok(report)
}

/// What `read_back` found for one name. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFound {
    /// The entry name.
    pub name: String,
    /// Its latest version, or `None` if the store does not have it.
    pub version: Option<u32>,
    /// The latest value exists and is not empty.
    pub non_empty: bool,
}

/// Prove the names are in the store: version and that the value is not empty,
/// nothing more.
pub fn read_back_secrets(store: &FileStore, names: &[&str]) -> Vec<SecretFound> {
    names
        .iter()
        .map(|n| {
            let version = store.describe(n).ok().map(|i| i.latest);
            let non_empty = store.get(n).map(|v| !v.is_empty()).unwrap_or(false);
            SecretFound {
                name: (*n).to_string(),
                version,
                non_empty,
            }
        })
        .collect()
}

fn generate(bytes: usize, encoding: Encoding) -> Result<SecretValue, SecretsError> {
    let mut raw = zeroize::Zeroizing::new(vec![0u8; bytes]);
    getrandom::fill(&mut raw).map_err(|_| SecretsError::Io)?;
    let text = match encoding {
        Encoding::Base64 => base64_standard(&raw),
        Encoding::Hex => raw.iter().map(|b| format!("{b:02x}")).collect(),
    };
    Ok(SecretValue::from_string(text))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_standard(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_vectors() {
        // RFC 4648 section 10.
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_standard(i.as_bytes()), o);
        }
        assert_eq!(base64_standard(&[0xfb, 0xff, 0xfe]), "+//+");
    }
}
