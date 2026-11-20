// SPDX-License-Identifier: MIT OR Apache-2.0
use secretant::{FileStore, KdfParams, ReadConfig, ReadUnlock, SecretReader, SecretValue, Store};
use std::{collections::BTreeMap, time::Duration};

#[rustfmt::skip]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = tempfile::tempdir()?.keep().join("store.json");
    let pass = || SecretValue::from_string("a long passphrase".into());
    let cheap = KdfParams { m_kib: 64, t: 1, p: 1 }; // example only; `create` has safe defaults
    let mut store = FileStore::create_with_params(&path, &pass(), cheap)?;
    store.put("API_TOKEN", SecretValue::from_string("s3cret".into()), BTreeMap::new())?;
    let config = ReadConfig { path, unlock: ReadUnlock::Passphrase(pass()), timeout: Duration::from_secs(10) };
    assert_eq!(SecretReader::open(config)?.get("API_TOKEN")?.expose(), b"s3cret");
    Ok(())
}
