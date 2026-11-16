// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `secretant` command line (ROADMAP row 4).
//!
//! `init`, `put`, `get`, `list`, `rotate`, `run NAME[,NAME] -- command args`.
//!
//! Rules this file keeps:
//! - A value is never an argument: `put` and `rotate` read it from standard
//!   input, so it is not in the process list or the shell history.
//! - `list` prints names only. Every error prints a fixed sentence about the
//!   class of failure: no name, no value, no file text.
//! - `run` puts each value in the child's environment only. The unlock secret
//!   (`SECRETANT_PASSPHRASE`) is removed from the child's environment.
//!
//! `deliver` reads a manifest `{"placements":[{"name":"N","file":"PATH"},
//! {"name":"N","env_file":"PATH","var":"VAR"}]}` and keeps its ledger in
//! `MANIFEST.ledger.json`.
//!
//! `cloudflare` reads `{"account_id":"A","script":"S","token":"STORE_NAME",
//! "secrets":[{"name":"STORE_NAME","var":"WORKER_VAR"}]}`; the API token is a stored
//! secret. Worker secrets are write-only, so `verify` says set, unset or stale.
//!
//! Unlock: by default the passphrase is asked on the terminal with no echo
//! (`put` and `rotate` also ask the value that way when standard input is a
//! terminal). With no terminal there is no silent fallback: choose
//! `--passphrase-stdin` (first line of standard input), `--recovery-stdin`
//! (first line), `--os` (Windows user account) or `--passphrase-env` (the
//! variable `SECRETANT_PASSPHRASE`, only when asked for by name).
//! Store file: `--store PATH`, else `SECRETANT_STORE`, else the per-user default.

use secretant::{
    Action, DeliverError, FileStore, ImportConflict, Ledger, Level, Placement, SecretValue, State,
    Store, StoreError, Target, Unlock,
};
#[cfg(feature = "cloudflare")]
use secretant::{CloudflareError, CloudflareWorker};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

mod prompt;
use prompt::{Ask, AskError, Terminal};

/// The command line. Parsed by `clap`; the help text is what `--help` prints.
///
/// If several unlock options are given, the first of `--passphrase-stdin`,
/// `--recovery-stdin`, `--os`, `--passphrase-env` (in that order) is used.
///
/// A value is never an argument, so a command that takes one reads it from
/// standard input or the terminal. A parse error prints one fixed sentence and
/// never echoes what was typed.
#[derive(clap::Parser)]
#[command(
    name = "secretant",
    version,
    about = "One place, controlled by its owner, where secrets live"
)]
struct Cli {
    /// The store file (else SECRETANT_STORE, else the per-user default)
    #[arg(long, global = true, value_name = "PATH")]
    store: Option<PathBuf>,
    /// Read the passphrase from the first line of standard input
    #[arg(long, global = true)]
    passphrase_stdin: bool,
    /// Read the recovery key from the first line of standard input
    #[arg(long, global = true)]
    recovery_stdin: bool,
    /// Unlock with the Windows user account
    #[arg(long, global = true)]
    os: bool,
    /// Take the passphrase from the variable SECRETANT_PASSPHRASE
    #[arg(long, global = true)]
    passphrase_env: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Plan,
    Apply,
    Verify,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum Conflict {
    Keep,
    Replace,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// Create a store (the new passphrase is asked twice on the terminal)
    Init {
        /// Also add a recovery key, shown once
        #[arg(long)]
        recovery: bool,
        /// Also add the Windows user-account wrap
        #[arg(long)]
        add_os: bool,
    },
    /// Add a version; the value is asked (no echo) or read from standard input
    Put { name: String },
    /// Like put, but NAME must already exist
    Rotate { name: String },
    /// Print the value to standard output
    Get {
        name: String,
        /// A specific version
        #[arg(long)]
        version: Option<u32>,
    },
    /// Print the names
    List,
    /// Run a command with each NAME as an environment variable
    Run {
        /// NAME or NAME,NAME
        names: String,
        /// The command and its arguments, after `--`
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Copy the store file (ciphertext) to DEST; needs no unlock
    Backup { dest: String },
    /// Open BACKUP and decrypt every version; prints counts
    RestoreTest { backup: String },
    /// Put BACKUP in place of the store (the old file is kept as .prev)
    Restore {
        backup: String,
        #[arg(long)]
        replace: bool,
    },
    /// Check the store file
    Doctor {
        /// Skip unlocking
        #[arg(long)]
        header_only: bool,
    },
    /// Write every entry to a new store file under its own passphrase
    Export {
        bundle: String,
        #[arg(long)]
        bundle_passphrase_stdin: bool,
    },
    /// Show what an import would do; --apply does it (nothing is deleted)
    Import {
        bundle: String,
        #[arg(long)]
        apply: bool,
        #[arg(long, value_enum)]
        conflict: Option<Conflict>,
        #[arg(long)]
        bundle_passphrase_stdin: bool,
    },
    /// Set a Cloudflare Worker's secrets from the store; prints names and states, never values
    Cloudflare { mode: Mode, manifest: String },
    /// Place values in files named by a JSON manifest; prints names and states, never values
    Deliver { mode: Mode, manifest: String },
}

/// Exit codes: 0 done, 1 refused or failed, 2 wrong usage.
fn main() -> ExitCode {
    use clap::{Parser, error::ErrorKind};
    let cli = match Cli::try_parse_from(std::env::args_os()) {
        Ok(c) => c,
        Err(e) if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
            print!("{e}");
            return ExitCode::SUCCESS;
        }
        Err(_) => return usage(),
    };
    match go(cli, &mut Terminal) {
        Ok(code) => code,
        Err(Fail::Usage) => usage(),
        Err(Fail::Store(e)) => {
            eprintln!("secretant: {e}");
            ExitCode::from(1)
        }
        Err(Fail::Text(t)) => {
            eprintln!("secretant: {t}");
            ExitCode::from(1)
        }
    }
}

/// One fixed sentence: what was typed is never echoed.
fn usage() -> ExitCode {
    eprintln!("secretant: wrong usage; run `secretant --help`");
    ExitCode::from(2)
}

enum Fail {
    Usage,
    Store(StoreError),
    Text(&'static str),
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Self {
        Fail::Store(e)
    }
}

enum How {
    Passphrase,
    Recovery,
    Os,
    Env,
    Prompt,
}

/// Standard input, read in the order the command needs it.
struct Input(std::io::Stdin);

impl Input {
    /// One line, without its line ending.
    fn line(&mut self) -> Result<SecretValue, Fail> {
        let mut bytes = Vec::new();
        let mut one = [0u8; 1];
        let mut lock = self.0.lock();
        loop {
            match lock.read(&mut one) {
                Ok(0) => break,
                Ok(_) if one[0] == b'\n' => break,
                Ok(_) => bytes.push(one[0]),
                Err(_) => return Err(Fail::Store(StoreError::Io)),
            }
        }
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        Ok(SecretValue::new(bytes))
    }

    /// Everything that is left, minus one final line ending (so a multi-line
    /// secret such as a key file keeps its inner lines).
    fn rest(&mut self) -> Result<SecretValue, Fail> {
        let mut bytes = Vec::new();
        self.0
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|_| Fail::Store(StoreError::Io))?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        Ok(SecretValue::new(bytes))
    }
}

/// An empty passphrase protects nothing: refuse it wherever one is taken.
fn nonempty(p: SecretValue) -> Result<SecretValue, Fail> {
    if p.is_empty() {
        Err(Fail::Text("an empty passphrase is not allowed"))
    } else {
        Ok(p)
    }
}

fn env_passphrase() -> Result<SecretValue, Fail> {
    let p = std::env::var("SECRETANT_PASSPHRASE")
        .map_err(|_| Fail::Text("SECRETANT_PASSPHRASE is not set"))?;
    nonempty(SecretValue::from_string(p))
}

fn default_store() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SECRETANT_STORE") {
        return Some(PathBuf::from(p));
    }
    #[cfg(windows)]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    base.map(|b| b.join("secretant").join("store.json"))
}

fn ask_fail(e: AskError) -> Fail {
    Fail::Text(match e {
        AskError::NoTerminal => {
            "no terminal to ask on: use --passphrase-stdin, --passphrase-env, --recovery-stdin or --os"
        }
        AskError::Failed => "the terminal could not be read",
        AskError::Mismatch => "the two passphrases differ; nothing was created",
        AskError::Empty => "an empty passphrase is not allowed; nothing was created",
    })
}

fn open(
    path: &PathBuf,
    how: &How,
    input: &mut Input,
    ask: &mut dyn Ask,
) -> Result<FileStore, Fail> {
    match how {
        How::Os => Ok(FileStore::open_with(path, Unlock::Os)?),
        How::Recovery => {
            let k = input.line()?;
            Ok(FileStore::open_with(path, Unlock::Recovery(&k))?)
        }
        How::Passphrase => {
            let p = nonempty(input.line()?)?;
            Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
        }
        How::Env => {
            let p = env_passphrase()?;
            Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
        }
        How::Prompt => {
            let p = prompt::passphrase(ask).map_err(ask_fail)?;
            Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
        }
    }
}

/// Run `f` with the unlock `how` names, without opening a store.
fn with_unlock<T>(
    how: &How,
    input: &mut Input,
    ask: &mut dyn Ask,
    f: impl FnOnce(Unlock<'_>) -> Result<T, StoreError>,
) -> Result<T, Fail> {
    let r = match how {
        How::Os => f(Unlock::Os),
        How::Recovery => {
            let k = input.line()?;
            f(Unlock::Recovery(&k))
        }
        How::Passphrase => {
            let p = nonempty(input.line()?)?;
            f(Unlock::Passphrase(&p))
        }
        How::Env => {
            let p = env_passphrase()?;
            f(Unlock::Passphrase(&p))
        }
        How::Prompt => {
            let p = prompt::passphrase(ask).map_err(ask_fail)?;
            f(Unlock::Passphrase(&p))
        }
    };
    Ok(r?)
}

/// Where a bundle's passphrase comes from.
enum BundleSource {
    /// The next line of standard input (`--bundle-passphrase-stdin`).
    Stdin,
    /// Asked on the terminal, twice, for a bundle being made.
    NewOnTerminal,
    /// Asked on the terminal, once, for a bundle being opened.
    ExistingOnTerminal,
}

/// The passphrase of a bundle, from where `source` says.
fn bundle_passphrase(
    source: BundleSource,
    input: &mut Input,
    ask: &mut dyn Ask,
) -> Result<SecretValue, Fail> {
    match source {
        BundleSource::Stdin => nonempty(input.line()?),
        BundleSource::NewOnTerminal => prompt::new_bundle_passphrase(ask).map_err(ask_fail),
        BundleSource::ExistingOnTerminal => prompt::bundle_passphrase(ask).map_err(ask_fail),
    }
}

fn go(cli: Cli, ask: &mut dyn Ask) -> Result<ExitCode, Fail> {
    let how = if cli.passphrase_stdin {
        How::Passphrase
    } else if cli.recovery_stdin {
        How::Recovery
    } else if cli.os {
        How::Os
    } else if cli.passphrase_env {
        How::Env
    } else {
        How::Prompt
    };
    let path = cli.store.or_else(default_store).ok_or(Fail::Usage)?;
    let mut input = Input(std::io::stdin());

    let is_rotate = matches!(cli.command, Cmd::Rotate { .. });
    match cli.command {
        Cmd::Init {
            recovery: want_recovery,
            add_os: want_os,
        } => {
            let pass = match how {
                How::Passphrase => nonempty(input.line()?)?,
                How::Env => env_passphrase()?,
                How::Prompt => prompt::new_passphrase(ask).map_err(ask_fail)?,
                _ => return Err(Fail::Usage),
            };
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let mut s = FileStore::create(&path, &pass)?;
            if want_os {
                s.add_os_wrap()?;
            }
            if want_recovery {
                // Shown once, here, and stored nowhere readable.
                let key = s.add_recovery_wrap()?;
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(key.expose());
                let _ = out.write_all(b"\n");
                eprintln!(
                    "secretant: keep the recovery key above somewhere safe; it is not shown again"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Put { name } | Cmd::Rotate { name } => {
            let mut s = open(&path, &how, &mut input, ask)?;
            if is_rotate {
                s.describe(&name)?;
            }
            let value = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                ask.secret("Value: ").map_err(ask_fail)?
            } else {
                input.rest()?
            };
            let v = s.put(&name, value, BTreeMap::new())?;
            println!("version {v}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Get { name, version } => {
            let s = open(&path, &how, &mut input, ask)?;
            let value = match version {
                Some(v) => s.get_version(&name, v)?,
                None => s.get(&name)?,
            };
            let mut out = std::io::stdout().lock();
            out.write_all(value.expose())
                .map_err(|_| Fail::Store(StoreError::Io))?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::List => {
            let s = open(&path, &how, &mut input, ask)?;
            for n in s.list() {
                println!("{n}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Backup { dest } => {
            secretant::backup(&path, std::path::Path::new(&dest))?;
            println!("backup written");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::RestoreTest { backup } => {
            let sum = with_unlock(&how, &mut input, ask, |u| {
                secretant::check_backup(std::path::Path::new(&backup), u)
            })?;
            println!(
                "backup opens: {} entries, {} versions",
                sum.entries, sum.versions
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Restore { backup, replace } => {
            let sum = with_unlock(&how, &mut input, ask, |u| {
                secretant::restore(std::path::Path::new(&backup), &path, u, replace)
            })?;
            println!(
                "restored: {} entries, {} versions",
                sum.entries, sum.versions
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Doctor { header_only } => {
            let findings = if header_only {
                secretant::doctor(&path, None)
            } else {
                with_unlock(&how, &mut input, ask, |u| {
                    Ok(secretant::doctor(&path, Some(u)))
                })?
            };
            let mut worst = Level::Info;
            for f in &findings {
                let tag = match f.level {
                    Level::Info => "ok  ",
                    Level::Warn => "warn",
                    Level::Fail => "FAIL",
                    _ => "????",
                };
                println!("{tag} {}", f.hint);
                worst = worst.max(f.level);
            }
            Ok(if worst == Level::Fail {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Export {
            bundle: dest,
            bundle_passphrase_stdin: from_stdin,
        } => {
            let s = open(&path, &how, &mut input, ask)?;
            let source = if from_stdin {
                BundleSource::Stdin
            } else {
                BundleSource::NewOnTerminal
            };
            let bp = bundle_passphrase(source, &mut input, ask)?;
            let mut bundle = FileStore::create(std::path::Path::new(&dest), &bp)?;
            s.export_to(&mut bundle)?;
            println!("exported {} entries", s.list().len());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import {
            bundle: src,
            apply,
            conflict,
            bundle_passphrase_stdin: from_stdin,
        } => {
            let conflict = match conflict {
                None => ImportConflict::Refuse,
                Some(Conflict::Keep) => ImportConflict::Keep,
                Some(Conflict::Replace) => ImportConflict::Replace,
            };
            let mut s = open(&path, &how, &mut input, ask)?;
            let source = if from_stdin {
                BundleSource::Stdin
            } else {
                BundleSource::ExistingOnTerminal
            };
            let bp = bundle_passphrase(source, &mut input, ask)?;
            let bundle = FileStore::open_with(std::path::Path::new(&src), Unlock::Passphrase(&bp))?;
            if apply {
                let r = s.apply_import(&bundle, conflict)?;
                println!(
                    "imported: {} added, {} replaced, {} kept",
                    r.added, r.replaced, r.kept
                );
            } else {
                for item in s.plan_import(&bundle) {
                    let what = if item.exists { "exists" } else { "new" };
                    println!("{what:6} {} ({} versions)", item.name, item.versions);
                }
                println!("dry run: nothing was written; add --apply to import");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run {
            names: list,
            command,
        } => {
            let Some((program, program_args)) = command.split_first() else {
                return Err(Fail::Usage);
            };
            let s = open(&path, &how, &mut input, ask)?;
            let mut child = Command::new(program);
            child.args(program_args);
            child.env_remove("SECRETANT_PASSPHRASE");
            for name in list.split(',') {
                let ok_name = !name.is_empty()
                    && !name.starts_with(|c: char| c.is_ascii_digit())
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                if !ok_name {
                    return Err(Fail::Text(
                        "a name given to run must be a valid environment variable name",
                    ));
                }
                let v = s.get(name)?;
                let text = std::str::from_utf8(v.expose())
                    .map_err(|_| Fail::Text("a value given to run is not text"))?;
                child.env(name, text);
            }
            drop(s);
            let status = child
                .status()
                .map_err(|_| Fail::Text("the command could not be started"))?;
            Ok(ExitCode::from(
                status.code().map_or(1, |c| u8::try_from(c).unwrap_or(1)),
            ))
        }
        #[cfg(not(feature = "cloudflare"))]
        Cmd::Cloudflare { .. } => Err(Fail::Text(
            "this build has no Cloudflare support: build with --features cloudflare",
        )),
        #[cfg(feature = "cloudflare")]
        Cmd::Cloudflare { mode, manifest } => {
            let (worker, token, mappings) = read_cf_manifest(&manifest)?;
            let s = open(&path, &how, &mut input, ask)?;
            let mut ledger_name = std::ffi::OsString::from(&manifest);
            ledger_name.push(".ledger.json");
            let mut ledger = Ledger::open(PathBuf::from(ledger_name)).map_err(deliver_fail)?;
            let cf_fail = |e: CloudflareError| match e {
                CloudflareError::Store(s) => Fail::Store(s),
                CloudflareError::Denied => Fail::Text("Cloudflare refused the token"),
                CloudflareError::NotFound => Fail::Text("Cloudflare has no such account or Worker"),
                CloudflareError::RateLimited => Fail::Text("Cloudflare rate-limited the request"),
                CloudflareError::Unreachable => Fail::Text("Cloudflare could not be reached"),
                CloudflareError::TimedOut => Fail::Text("the request to Cloudflare timed out"),
                CloudflareError::Rejected => Fail::Text("Cloudflare answered with an error"),
                CloudflareError::Unsupported => {
                    Fail::Text("a name or value cannot be sent to a Worker")
                }
                CloudflareError::Ledger => Fail::Text("the delivery ledger could not be written"),
                _ => Fail::Text("Cloudflare delivery failed"),
            };
            let mut bad = false;
            match mode {
                Mode::Plan => {
                    for (i, a) in secretant::cf::plan(&s, &ledger, &worker, &token, &mappings)
                        .map_err(cf_fail)?
                    {
                        let word = match a {
                            Action::Create => "create",
                            Action::Update => "update",
                            Action::Unchanged => "unchanged",
                            _ => "unknown",
                        };
                        println!("{} {word}", mappings[i].0);
                    }
                }
                Mode::Apply => {
                    let n = secretant::cf::apply(&s, &mut ledger, &worker, &token, &mappings)
                        .map_err(cf_fail)?;
                    println!("sent {n} secret(s)");
                }
                Mode::Verify => {
                    for (i, st) in secretant::cf::verify(&s, &ledger, &worker, &token, &mappings)
                        .map_err(cf_fail)?
                    {
                        let word = match st {
                            State::InSync => "set",
                            State::Stale => "stale",
                            State::Missing => "unset",
                            _ => "unknown",
                        };
                        bad |= st != State::InSync;
                        println!("{} {word}", mappings[i].0);
                    }
                }
            }
            Ok(if bad {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Deliver { mode, manifest } => {
            let placements = read_manifest(&manifest)?;
            let s = open(&path, &how, &mut input, ask)?;
            let mut ledger_name = std::ffi::OsString::from(&manifest);
            ledger_name.push(".ledger.json");
            let mut ledger = Ledger::open(PathBuf::from(ledger_name)).map_err(deliver_fail)?;
            let mut bad = false;
            match mode {
                Mode::Plan => {
                    for (i, a) in secretant::plan(&s, &ledger, &placements) {
                        let word = match a {
                            Action::Create => "create",
                            Action::Update => "update",
                            Action::Unchanged => "unchanged",
                            _ => "unknown",
                        };
                        println!("{} {word}", placements[i].name);
                    }
                }
                Mode::Apply => {
                    for o in secretant::apply(&s, &mut ledger, &placements) {
                        match o.result {
                            Ok(v) => println!("{} placed version {v}", placements[o.index].name),
                            Err(e) => {
                                bad = true;
                                println!("{} failed: {e}", placements[o.index].name);
                            }
                        }
                    }
                }
                Mode::Verify => {
                    for (i, st) in secretant::verify(&s, &ledger, &placements) {
                        let word = match st {
                            State::InSync => "in-sync",
                            State::Stale => "stale",
                            State::Drifted => "drifted",
                            State::Missing => "missing",
                            State::LoosePerms => "loose-permissions",
                            State::Unreadable => "unreadable",
                            _ => "unknown",
                        };
                        bad |= st != State::InSync;
                        println!("{} {word}", placements[i].name);
                    }
                }
            }
            Ok(if bad {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

fn deliver_fail(e: DeliverError) -> Fail {
    match e {
        DeliverError::Store(s) => Fail::Store(s),
        DeliverError::Io => Fail::Text("a target could not be read or written"),
        DeliverError::Unsupported => Fail::Text("the value does not fit that kind of target"),
        _ => Fail::Text("delivery failed"),
    }
}

#[derive(serde::Deserialize)]
struct ManifestFile {
    placements: Vec<ManifestEntry>,
}

#[derive(serde::Deserialize)]
struct ManifestEntry {
    name: String,
    file: Option<PathBuf>,
    env_file: Option<PathBuf>,
    var: Option<String>,
}

fn read_manifest(path: &str) -> Result<Vec<Placement>, Fail> {
    let bytes = std::fs::read(path).map_err(|_| Fail::Text("the manifest could not be read"))?;
    let m: ManifestFile =
        serde_json::from_slice(&bytes).map_err(|_| Fail::Text("the manifest is not valid"))?;
    m.placements
        .into_iter()
        .map(|e| {
            let target = match (e.file, e.env_file, e.var) {
                (Some(p), None, None) => Target::File(p),
                (None, Some(path), Some(var)) => Target::EnvFile { path, var },
                _ => return Err(Fail::Text("the manifest is not valid")),
            };
            Ok(Placement {
                name: e.name,
                target,
            })
        })
        .collect()
}

#[cfg(feature = "cloudflare")]
#[derive(serde::Deserialize)]
struct CfManifest {
    account_id: String,
    script: String,
    token: String,
    secrets: Vec<CfEntry>,
}

#[cfg(feature = "cloudflare")]
#[derive(serde::Deserialize)]
struct CfEntry {
    name: String,
    var: String,
}

#[cfg(feature = "cloudflare")]
type CfPlan = (CloudflareWorker, String, Vec<(String, String)>);

#[cfg(feature = "cloudflare")]
fn read_cf_manifest(path: &str) -> Result<CfPlan, Fail> {
    let bytes = std::fs::read(path).map_err(|_| Fail::Text("the manifest could not be read"))?;
    let m: CfManifest =
        serde_json::from_slice(&bytes).map_err(|_| Fail::Text("the manifest is not valid"))?;
    let worker = CloudflareWorker::new(m.account_id, m.script);
    Ok((
        worker,
        m.token,
        m.secrets.into_iter().map(|e| (e.name, e.var)).collect(),
    ))
}
