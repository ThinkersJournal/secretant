// SPDX-License-Identifier: MIT OR Apache-2.0
//! The agent-facing face of SecretAnt (board 498 A; boundary: capant's
//! `THREAT-NOTE-VAULT-TOOL.md`; design: `docs/DESIGN-VAULT-TOOL.md`).
//!
//! Four tools, and only these exist in the code: [`Face::list_names`],
//! [`Face::ledger_read`], [`Face::verify_placement`] and [`Face::deliver`].
//! There is no tool that returns a value, in any form, and no put, rotate,
//! import, export, backup, restore, unlock or Cloudflare tool. Every response
//! type below holds names, paths, numbers and fixed status words: none has a
//! field that could carry a value, and [`secretant::SecretValue`] is never
//! given a `Display` or `Serialize` here.
//!
//! This crate is the tool layer only (transport-independent): [`Face::call`]
//! maps a tool name and JSON arguments to a JSON result, and a thin MCP shim
//! serves that. The host opens the store (an [`Opener`]); no argument names a
//! store, an unlock or an allow-list.
//!
//! # Interim gate (`permission-policy` has no provider yet)
//! The named stand-in for `permission-policy`: [`HostConfig`] carries a role
//! and the name prefixes that role may see, plus the allow-listed directories.
//! [`HostConfig::new`] refuses an empty role or an empty prefix set, so no
//! [`Face`] exists without a configured role; every tool then checks the
//! prefix scope (and delivery, verification the allow-list) on every call.
//!
//! # Limits stated up front
//! - A check on a path and the write that follows it are not atomic (a time
//!   of check, time of use gap): a same-user program can swap a directory in
//!   between. This is SecretAnt's same-user limit, not closed here.
//! - A granted approval is for one placement per path per call; the
//!   [`PlacementApprover`] decides what the person is shown.

#[cfg(feature = "stdio")]
pub mod serve;
pub mod subject;

use secretant::{DeliverError, Ledger, Placement, State, Store, StoreError, Target};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A directory the face may place files in.
#[derive(Debug, Clone)]
pub struct AllowRoot {
    /// The directory.
    pub path: PathBuf,
    /// The host declares the agent's file tool cannot read it. A root without
    /// this is refused (fail closed): a delivered secret in a place the agent
    /// can read back is a value returned by another route.
    pub agent_unreadable: bool,
}

/// Why a [`HostConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// No role, or no name prefix for it: the face will not run unscoped.
    NoRole,
}

/// What the host sets: not reachable from a tool argument.
#[derive(Debug, Clone)]
pub struct HostConfig {
    role: String,
    prefixes: Vec<String>,
    roots: Vec<AllowRoot>,
    ledger_path: PathBuf,
    record_path: PathBuf,
}

impl HostConfig {
    /// A role, the name prefixes it may see (each non-empty), the allow-list,
    /// the delivery ledger and the face's own record file.
    pub fn new(
        role: &str,
        prefixes: &[&str],
        roots: Vec<AllowRoot>,
        ledger_path: PathBuf,
        record_path: PathBuf,
    ) -> Result<Self, ConfigError> {
        if role.trim().is_empty() || prefixes.is_empty() || prefixes.iter().any(|p| p.is_empty()) {
            return Err(ConfigError::NoRole);
        }
        Ok(Self {
            role: role.to_string(),
            prefixes: prefixes.iter().map(|p| (*p).to_string()).collect(),
            roots,
            ledger_path,
            record_path,
        })
    }
}

/// What the person is asked to approve: one name to one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementRequest {
    /// Who asked (the configured role).
    pub role: String,
    /// The secret's name (never its value).
    pub name: String,
    /// The resolved target path.
    pub path: PathBuf,
    /// The variable, for an environment file.
    pub var: Option<String>,
    /// `NAME -> path`, built by [`subject::format`]: exactly what the person
    /// is asked to approve, whole.
    pub subject: String,
}

/// A person's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Approved for this one placement.
    Approved,
    /// Refused.
    Denied,
    /// No answer in time.
    TimedOut,
    /// The channel cannot ask (no Windows Hello, say).
    Unavailable,
}

/// Asks a person, per target path. The tool-enforced prompt (Windows Hello via
/// `user-request`) is one implementation, kept behind this trait so the face
/// can be tested and the prompt swapped (slice 1 reuses its `Secret` kind with
/// the shortest grant the kind allows).
pub trait PlacementApprover: Send + Sync {
    /// Ask once for this placement.
    fn approve(&self, req: &PlacementRequest) -> Decision;
}

/// Refuses everything: the safe default when no channel is wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl PlacementApprover for DenyAll {
    fn approve(&self, _: &PlacementRequest) -> Decision {
        Decision::Denied
    }
}

/// How the host opens the store for one call. The face keeps no store and no
/// value between calls.
pub type Opener = Box<dyn Fn() -> Result<Box<dyn Store>, StoreError> + Send + Sync>;

/// A fixed failure class: a word, never text built from a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ToolError {
    /// The name is outside the role's prefix scope.
    OutOfScope,
    /// No such name.
    NoSuchName,
    /// The path is not absolute, has `..`, or its directory is missing.
    BadPath,
    /// The path is outside every allow-listed, agent-unreadable root, or is a
    /// symlink or directory.
    PathNotAllowed,
    /// The person refused.
    Denied,
    /// The person did not answer.
    TimedOut,
    /// No approval channel could ask.
    ApprovalUnavailable,
    /// The face's own record could not be written; nothing was done.
    RecordFailed,
    /// The target was not owner-only after writing; delivery failed closed.
    NotPrivate,
    /// The value does not fit that kind of target.
    Unsupported,
    /// The store could not be opened or read.
    StoreError,
    /// A file could not be read or written.
    Io,
    /// The tool name or its arguments are not understood.
    BadRequest,
}

/// One placement an agent names. A name and a path, never a value.
#[derive(Debug, Clone, Deserialize)]
pub struct PlacementArg {
    /// The store name.
    pub name: String,
    /// Absolute target path.
    pub path: String,
    /// Set for an environment file: the variable that placement owns.
    #[serde(default)]
    pub var: Option<String>,
}

/// One ledger row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerRow {
    /// The store name.
    pub name: String,
    /// `file:<path>` or `env:<path>#<VAR>`.
    pub target: String,
    /// The version placed.
    pub version: u32,
}

/// One placement's result: a status word, never a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlacementStatus {
    /// The name asked about.
    pub name: String,
    /// The path asked about.
    pub path: String,
    /// `in-sync`, `stale`, `drifted`, `missing`, `loose-perms`, `unreadable`,
    /// `placed`, or a [`ToolError`] word.
    pub status: String,
    /// The version placed (delivery only).
    pub version: Option<u32>,
}

/// The face.
pub struct Face {
    cfg: HostConfig,
    opener: Opener,
    approver: Box<dyn PlacementApprover>,
    record: Mutex<()>,
}

impl Face {
    /// Build the face from the host's choices.
    #[must_use]
    pub fn new(cfg: HostConfig, opener: Opener, approver: Box<dyn PlacementApprover>) -> Self {
        Self {
            cfg,
            opener,
            approver,
            record: Mutex::new(()),
        }
    }

    fn in_scope(&self, name: &str) -> bool {
        self.cfg
            .prefixes
            .iter()
            .any(|p| name.starts_with(p.as_str()))
    }

    /// Append one line to the face's own record. Names, paths and outcomes.
    fn record(&self, tool: &str, name: &str, target: &str, outcome: &str) -> Result<(), ToolError> {
        let _g = self.record.lock().map_err(|_| ToolError::RecordFailed)?;
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = json!({"at": at, "role": self.cfg.role, "tool": tool,
            "name": name, "target": target, "outcome": outcome});
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cfg.record_path)
            .map_err(|_| ToolError::RecordFailed)?;
        writeln!(f, "{line}").map_err(|_| ToolError::RecordFailed)?;
        f.sync_all().map_err(|_| ToolError::RecordFailed)
    }

    /// The names in the role's scope.
    pub fn list_names(&self) -> Result<Vec<String>, ToolError> {
        self.record("list_names", "", "", "asked")?;
        let store = (self.opener)().map_err(|_| ToolError::StoreError)?;
        Ok(store
            .list()
            .into_iter()
            .filter(|n| self.in_scope(n))
            .collect())
    }

    /// What was placed where, for the role's names.
    pub fn ledger_read(&self) -> Result<Vec<LedgerRow>, ToolError> {
        self.record("ledger_read", "", "", "asked")?;
        let ledger = Ledger::open(&self.cfg.ledger_path).map_err(|_| ToolError::Io)?;
        Ok(ledger
            .entries()
            .into_iter()
            .filter(|(n, _, _)| self.in_scope(n))
            .map(|(name, target, version)| LedgerRow {
                name,
                target,
                version,
            })
            .collect())
    }

    /// Whether each placement matches the store's latest value: a status word.
    pub fn verify_placement(
        &self,
        args: &[PlacementArg],
    ) -> Result<Vec<PlacementStatus>, ToolError> {
        self.record("verify_placement", "", "", "asked")?;
        let store = (self.opener)().map_err(|_| ToolError::StoreError)?;
        let ledger = Ledger::open(&self.cfg.ledger_path).map_err(|_| ToolError::Io)?;
        Ok(args
            .iter()
            .map(|a| match self.prepare(a) {
                Err(e) => status(a, word(e), None),
                Ok(p) => {
                    let s = secretant::verify(&*store, &ledger, std::slice::from_ref(&p));
                    status(a, state_word(s[0].1), None)
                }
            })
            .collect())
    }

    /// Place the named secrets at the named files, after the person approves
    /// each path. Values go from the store to the file and nowhere else.
    pub fn deliver(&self, args: &[PlacementArg]) -> Result<Vec<PlacementStatus>, ToolError> {
        let mut out = Vec::new();
        let mut asked: BTreeSet<PathBuf> = BTreeSet::new();
        let mut ready: Vec<(usize, Placement)> = Vec::new();
        for (i, a) in args.iter().enumerate() {
            let p = match self.prepare(a) {
                Ok(p) => p,
                Err(e) => {
                    self.record("deliver", &a.name, &a.path, word(e))?;
                    out.push(status(a, word(e), None));
                    continue;
                }
            };
            let path = target_path(&p).to_path_buf();
            let Ok(subject) = subject::format(&a.name, &path) else {
                self.record("deliver", &a.name, &a.path, word(ToolError::BadPath))?;
                out.push(status(a, word(ToolError::BadPath), None));
                continue;
            };
            let req = PlacementRequest {
                role: self.cfg.role.clone(),
                name: a.name.clone(),
                path: path.clone(),
                var: a.var.clone(),
                subject,
            };
            // Record the request before asking: a record that cannot be
            // written stops the call before anything is shown or done.
            self.record("deliver", &a.name, &a.path, "asked")?;
            let _ = asked.insert(path);
            let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.approver.approve(&req)
            }))
            .unwrap_or(Decision::Unavailable);
            match decision {
                Decision::Approved => {
                    out.push(status(a, "pending", None));
                    ready.push((i, p));
                }
                Decision::Denied => self.refuse(&mut out, a, ToolError::Denied)?,
                Decision::TimedOut => self.refuse(&mut out, a, ToolError::TimedOut)?,
                Decision::Unavailable => {
                    self.refuse(&mut out, a, ToolError::ApprovalUnavailable)?
                }
            }
        }
        if ready.is_empty() {
            return Ok(out);
        }
        let store = (self.opener)().map_err(|_| ToolError::StoreError)?;
        let mut ledger = Ledger::open(&self.cfg.ledger_path).map_err(|_| ToolError::Io)?;
        for (i, p) in ready {
            let arg = &args[i];
            // Re-check at write: the path approved must still resolve to the
            // same canonical target (a swapped directory or a new symlink fails).
            match self.prepare(arg) {
                Ok(again) if again == p => {}
                _ => {
                    self.record(
                        "deliver",
                        &arg.name,
                        &arg.path,
                        word(ToolError::PathNotAllowed),
                    )?;
                    if let Some(slot) = out.get_mut(i) {
                        *slot = status(arg, word(ToolError::PathNotAllowed), None);
                    }
                    continue;
                }
            }
            let existed = target_path(&p).exists();
            let result = secretant::apply(&*store, &mut ledger, std::slice::from_ref(&p));
            let (word_, version) = match result[0].result {
                Err(e) => (deliver_word(e), None),
                Ok(v) => {
                    // Rule 4, checked after the write: owner-only or fail closed.
                    let again = secretant::verify(&*store, &ledger, std::slice::from_ref(&p));
                    if again[0].1 == State::InSync {
                        ("placed", Some(v))
                    } else {
                        if !existed && matches!(p.target, Target::File(_)) {
                            let _ = fs::remove_file(target_path(&p));
                        }
                        (word(ToolError::NotPrivate), None)
                    }
                }
            };
            self.record("deliver", &arg.name, &arg.path, word_)?;
            if let Some(slot) = out.get_mut(i) {
                *slot = status(arg, word_, version);
            }
        }
        Ok(out)
    }

    fn refuse(
        &self,
        out: &mut Vec<PlacementStatus>,
        a: &PlacementArg,
        e: ToolError,
    ) -> Result<(), ToolError> {
        self.record("deliver", &a.name, &a.path, word(e))?;
        out.push(status(a, word(e), None));
        Ok(())
    }

    /// Check scope and path; build the placement.
    fn prepare(&self, a: &PlacementArg) -> Result<Placement, ToolError> {
        if !self.in_scope(&a.name) {
            return Err(ToolError::OutOfScope);
        }
        let path = self.resolve(&a.path)?;
        let target = match &a.var {
            None => Target::File(path),
            Some(var) => Target::EnvFile {
                path,
                var: var.clone(),
            },
        };
        Ok(Placement {
            name: a.name.clone(),
            target,
        })
    }

    /// The canonical target: absolute, no `..`, directory exists and lies under
    /// an agent-unreadable allow-listed root, and the file is not a symlink.
    fn resolve(&self, raw: &str) -> Result<PathBuf, ToolError> {
        let p = Path::new(raw);
        if !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(ToolError::BadPath);
        }
        let file = p.file_name().ok_or(ToolError::BadPath)?;
        let parent = p.parent().ok_or(ToolError::BadPath)?;
        let parent = plain(fs::canonicalize(parent).map_err(|_| ToolError::BadPath)?);
        let allowed = self
            .cfg
            .roots
            .iter()
            .filter(|r| r.agent_unreadable)
            .any(|r| {
                fs::canonicalize(&r.path)
                    .map(plain)
                    .is_ok_and(|root| parent.starts_with(root))
            });
        if !allowed {
            return Err(ToolError::PathNotAllowed);
        }
        let full = parent.join(file);
        match fs::symlink_metadata(&full) {
            Ok(m) if m.file_type().is_symlink() || m.is_dir() => Err(ToolError::PathNotAllowed),
            Ok(_) => Ok(full),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(full),
            Err(_) => Err(ToolError::Io),
        }
    }

    /// The protocol entry the MCP shim serves: a tool name and its JSON
    /// arguments in, a JSON result out. Only the four tools are known.
    #[must_use]
    pub fn call(&self, tool: &str, args: &Value) -> Value {
        let placements = || -> Result<Vec<PlacementArg>, ToolError> {
            serde_json::from_value(args.get("placements").cloned().unwrap_or(Value::Null))
                .map_err(|_| ToolError::BadRequest)
        };
        let result = match tool {
            "list_names" => self.list_names().map(|v| json!({ "names": v })),
            "ledger_read" => self.ledger_read().map(|v| json!({ "rows": v })),
            "verify_placement" => placements()
                .and_then(|a| self.verify_placement(&a))
                .map(|v| json!({ "placements": v })),
            "deliver" => placements()
                .and_then(|a| self.deliver(&a))
                .map(|v| json!({ "placements": v })),
            _ => Err(ToolError::BadRequest),
        };
        match result {
            Ok(v) => v,
            Err(e) => json!({ "error": e }),
        }
    }
}

fn target_path(p: &Placement) -> &Path {
    match &p.target {
        Target::File(path) | Target::EnvFile { path, .. } => path,
    }
}

fn status(a: &PlacementArg, s: &str, version: Option<u32>) -> PlacementStatus {
    PlacementStatus {
        name: a.name.clone(),
        path: a.path.clone(),
        status: s.to_string(),
        version,
    }
}

fn word(e: ToolError) -> &'static str {
    match e {
        ToolError::OutOfScope => "out-of-scope",
        ToolError::NoSuchName => "no-such-name",
        ToolError::BadPath => "bad-path",
        ToolError::PathNotAllowed => "path-not-allowed",
        ToolError::Denied => "denied",
        ToolError::TimedOut => "timed-out",
        ToolError::ApprovalUnavailable => "approval-unavailable",
        ToolError::RecordFailed => "record-failed",
        ToolError::NotPrivate => "not-private",
        ToolError::Unsupported => "unsupported",
        ToolError::StoreError => "store-error",
        ToolError::Io => "io",
        ToolError::BadRequest => "bad-request",
    }
}

fn state_word(s: State) -> &'static str {
    match s {
        State::InSync => "in-sync",
        State::Stale => "stale",
        State::Drifted => "drifted",
        State::Missing => "missing",
        State::LoosePerms => "loose-perms",
        _ => "unreadable",
    }
}

fn deliver_word(e: DeliverError) -> &'static str {
    match e {
        DeliverError::Store(StoreError::NotFound) => word(ToolError::NoSuchName),
        DeliverError::Store(_) => word(ToolError::StoreError),
        DeliverError::Unsupported => word(ToolError::Unsupported),
        _ => word(ToolError::Io),
    }
}

/// Strip the Windows verbatim prefix `\\?\` that `canonicalize` adds, so paths
/// compare and print plainly. Other paths pass through.
fn plain(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => p,
    }
}
