// SPDX-License-Identifier: MIT OR Apache-2.0
//! Cloudflare Worker secret delivery (ROADMAP row 6).
//!
//! Checked against Cloudflare's published API reference on 2026-11-12 (the
//! "Workers script secrets" pages and the 2026-06-03 bulk-secrets changelog):
//!
//! - list: `GET /accounts/{account}/workers/scripts/{script}/secrets` returns
//!   names and types only, never a value;
//! - write: `PATCH .../secrets-bulk` with `{"secrets": {NAME: {"type":
//!   "secret_text", "name": NAME, "text": VALUE}}}` creates one new script
//!   version holding every change (all or nothing), at most 100 operations;
//! - write needs the token permission `Workers Scripts Write`; list needs a
//!   Workers read permission.
//!
//! Worker secrets are write-only, so `verify` can say a name is set or unset,
//! not that it equals the store's value. The ledger (which version was last
//! sent) is what tells a current secret from a stale one.
//!
//! The API token is a stored secret, passed per call and sent only in the
//! `Authorization` header. A secret value appears only in the request body.
//! Errors carry a class and never the response text.

use crate::deliver::{Action, Ledger, State, valid_var};
use crate::store::{Store, StoreError};
use crate::value::SecretValue;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_BASE: &str = "https://api.cloudflare.com/client/v4";
/// Cloudflare accepts at most this many operations in one bulk request.
pub const MAX_BULK: usize = 100;

/// Why a Cloudflare step failed. A class only: no response text, name or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudflareError {
    /// The token was refused (401 or 403): wrong, expired, or lacking scope.
    Denied,
    /// No such account or Worker (404).
    NotFound,
    /// Rate limited (429); nothing was changed.
    RateLimited,
    /// Cloudflare could not be reached.
    Unreachable,
    /// The request did not finish within the time allowed.
    TimedOut,
    /// Cloudflare answered with an error or something unexpected; nothing was recorded.
    Rejected,
    /// A name or value cannot be sent (bad variable name, a value that is not
    /// text, or more than [`MAX_BULK`] secrets).
    Unsupported,
    /// The store refused (missing name, wrong unlock).
    Store(StoreError),
    /// The ledger could not be written.
    Ledger,
}

impl From<StoreError> for CloudflareError {
    fn from(e: StoreError) -> Self {
        CloudflareError::Store(e)
    }
}

impl std::fmt::Display for CloudflareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CloudflareError::Denied => "Cloudflare refused the token",
            CloudflareError::NotFound => "Cloudflare has no such account or Worker",
            CloudflareError::RateLimited => "Cloudflare rate-limited the request",
            CloudflareError::Unreachable => "Cloudflare could not be reached",
            CloudflareError::TimedOut => "the request to Cloudflare timed out",
            CloudflareError::Rejected => "Cloudflare answered with an error",
            CloudflareError::Unsupported => "a name or value cannot be sent to a Worker",
            CloudflareError::Store(e) => return e.fmt(f),
            CloudflareError::Ledger => "the delivery ledger could not be written",
        })
    }
}

impl std::error::Error for CloudflareError {}

/// One Worker script on one account. Holds no token.
#[derive(Debug, Clone)]
pub struct CloudflareWorker {
    account_id: String,
    script: String,
    base_url: String,
    timeout: Duration,
}

impl CloudflareWorker {
    /// The Worker `script` on `account_id`, at Cloudflare's public API, 30 s per call.
    pub fn new(account_id: impl Into<String>, script: impl Into<String>) -> Self {
        CloudflareWorker {
            account_id: account_id.into(),
            script: script.into(),
            base_url: DEFAULT_BASE.to_string(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Use another API base (a test server). Not for production.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Bound each call. The client counts whole seconds, so this rounds up to one.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn url(&self, tail: &str) -> String {
        format!(
            "{}/accounts/{}/workers/scripts/{}/{tail}",
            self.base_url.trim_end_matches('/'),
            self.account_id,
            self.script
        )
    }

    /// The per-call limit in whole seconds (at least one), as the client takes it.
    fn secs(&self) -> u64 {
        self.timeout.as_millis().div_ceil(1000).max(1) as u64
    }

    fn key(&self, var: &str) -> String {
        format!("cf:{}/{}#{var}", self.account_id, self.script)
    }

    /// The names of the secrets bound to the Worker. Names only: Cloudflare
    /// never returns a value.
    pub fn list(&self, token: &SecretValue) -> Result<Vec<String>, CloudflareError> {
        let auth = bearer(token)?;
        let resp = minreq::get(self.url("secrets"))
            .with_header("Authorization", auth.as_str())
            .with_timeout(self.secs())
            .with_max_redirects(0)
            .send()
            .map_err(classify)?;
        let (status, body) = read(&resp);
        check(status)?;
        let v: serde_json::Value =
            serde_json::from_str(&body).map_err(|_| CloudflareError::Rejected)?;
        if v["success"] != serde_json::Value::Bool(true) {
            return Err(CloudflareError::Rejected);
        }
        let list = v["result"].as_array().ok_or(CloudflareError::Rejected)?;
        Ok(list
            .iter()
            .filter_map(|e| e["name"].as_str().map(str::to_string))
            .collect())
    }

    /// Set every `(variable, value)` in one request (one new script version:
    /// all or nothing). Needs `Workers Scripts Write`.
    pub fn put_all(
        &self,
        token: &SecretValue,
        secrets: &[(&str, &SecretValue)],
    ) -> Result<(), CloudflareError> {
        if secrets.is_empty() {
            return Ok(());
        }
        if secrets.len() > MAX_BULK {
            return Err(CloudflareError::Unsupported);
        }
        let mut map = serde_json::Map::new();
        for (var, value) in secrets {
            if !valid_var(var) {
                return Err(CloudflareError::Unsupported);
            }
            let text =
                std::str::from_utf8(value.expose()).map_err(|_| CloudflareError::Unsupported)?;
            map.insert(
                (*var).to_string(),
                serde_json::json!({"type": "secret_text", "name": var, "text": text}),
            );
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "secrets": map }))
                .map_err(|_| CloudflareError::Unsupported)?,
        );
        let auth = bearer(token)?;
        // The client takes the body by value; its copy is not wiped (a stated limit).
        let resp = minreq::patch(self.url("secrets-bulk"))
            .with_header("Authorization", auth.as_str())
            .with_header("Content-Type", "application/json")
            .with_body(body.to_vec())
            .with_timeout(self.secs())
            .with_max_redirects(0)
            .send()
            .map_err(classify)?;
        let (status, text) = read(&resp);
        check(status)?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| CloudflareError::Rejected)?;
        if v["success"] != serde_json::Value::Bool(true) {
            return Err(CloudflareError::Rejected);
        }
        Ok(())
    }
}

fn bearer(token: &SecretValue) -> Result<Zeroizing<String>, CloudflareError> {
    let t = std::str::from_utf8(token.expose()).map_err(|_| CloudflareError::Unsupported)?;
    if t.is_empty() || t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(CloudflareError::Unsupported);
    }
    Ok(Zeroizing::new(format!("Bearer {t}")))
}

fn read(resp: &minreq::Response) -> (u16, String) {
    let status = resp.status_code;
    (status, resp.as_str().unwrap_or_default().to_string())
}

fn check(status: u16) -> Result<(), CloudflareError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(CloudflareError::Denied),
        404 => Err(CloudflareError::NotFound),
        429 => Err(CloudflareError::RateLimited),
        _ => Err(CloudflareError::Rejected),
    }
}

fn classify(e: minreq::Error) -> CloudflareError {
    match e {
        minreq::Error::IoError(io)
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) =>
        {
            CloudflareError::TimedOut
        }
        _ => CloudflareError::Unreachable,
    }
}

/// A placement: the store name and the Worker variable it becomes.
pub type Mapping = (String, String);

fn needs_write(
    store: &dyn Store,
    ledger: &Ledger,
    worker: &CloudflareWorker,
    set: &[String],
    m: &Mapping,
) -> Result<(Action, u32), CloudflareError> {
    let latest = store.describe(&m.0)?.latest;
    let is_set = set.iter().any(|n| n == &m.1);
    let sent = ledger.version_by(&m.0, &worker.key(&m.1));
    let action = if !is_set {
        Action::Create
    } else if sent == Some(latest) {
        Action::Unchanged
    } else {
        Action::Update
    };
    Ok((action, latest))
}

/// What `apply` would do. Reads the Worker's secret names and the store;
/// writes nothing. Fails (and so would `apply`) if the token cannot list.
pub fn plan(
    store: &dyn Store,
    ledger: &Ledger,
    worker: &CloudflareWorker,
    token_name: &str,
    mappings: &[Mapping],
) -> Result<Vec<(usize, Action)>, CloudflareError> {
    let token = store.get(token_name)?;
    let set = worker.list(&token)?;
    mappings
        .iter()
        .enumerate()
        .map(|(i, m)| Ok((i, needs_write(store, ledger, worker, &set, m)?.0)))
        .collect()
}

/// Send every secret that is unset or older than the store's latest version, in
/// one request. The ledger is updated only after Cloudflare accepts the
/// request, so a failure leaves every secret as it was and still stale.
/// Returns how many were sent.
pub fn apply(
    store: &dyn Store,
    ledger: &mut Ledger,
    worker: &CloudflareWorker,
    token_name: &str,
    mappings: &[Mapping],
) -> Result<usize, CloudflareError> {
    let token = store.get(token_name)?;
    // Listing first proves the token works before any value leaves the machine.
    let set = worker.list(&token)?;
    let mut send: Vec<(&Mapping, u32, SecretValue)> = Vec::new();
    for m in mappings {
        let (action, latest) = needs_write(store, ledger, worker, &set, m)?;
        if action != Action::Unchanged {
            send.push((m, latest, store.get(&m.0)?));
        }
    }
    let batch: Vec<(&str, &SecretValue)> = send.iter().map(|(m, _, v)| (m.1.as_str(), v)).collect();
    worker.put_all(&token, &batch)?;
    for (m, latest, _) in &send {
        ledger
            .record_by(&m.0, &worker.key(&m.1), *latest)
            .map_err(|_| CloudflareError::Ledger)?;
    }
    Ok(send.len())
}

/// One state per mapping. Worker secrets are write-only, so the best a current
/// secret can be is [`State::InSync`] meaning "set, and the ledger says the
/// store's latest version was the one sent"; the value itself is not read back.
/// [`State::Missing`]: not set. [`State::Stale`]: set, but this ledger did not
/// send the latest version (an older one, or none recorded).
pub fn verify(
    store: &dyn Store,
    ledger: &Ledger,
    worker: &CloudflareWorker,
    token_name: &str,
    mappings: &[Mapping],
) -> Result<Vec<(usize, State)>, CloudflareError> {
    let token = store.get(token_name)?;
    let set = worker.list(&token)?;
    Ok(mappings
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let st = match needs_write(store, ledger, worker, &set, m) {
                Err(_) => State::Unreadable,
                Ok((Action::Create, _)) => State::Missing,
                Ok((Action::Unchanged, _)) => State::InSync,
                Ok((Action::Update, _)) => State::Stale,
            };
            (i, st)
        })
        .collect())
}
