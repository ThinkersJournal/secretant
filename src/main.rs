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
//! Unlock: `--passphrase-stdin` (first line of standard input), `--recovery-stdin`
//! (first line), `--os` (Windows user account), or, with none of these, the
//! environment variable `SECRETANT_PASSPHRASE` if set, else `--os`.
//! Store file: `--store PATH`, else `SECRETANT_STORE`, else the per-user default.

use secretant::{
    Action, DeliverError, FileStore, Ledger, Placement, SecretValue, State, Store, StoreError,
    Target, Unlock,
};
#[cfg(feature = "cloudflare")]
use secretant::{CloudflareError, CloudflareWorker};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const USAGE: &str =
    "usage: secretant [--store PATH] [--passphrase-stdin | --recovery-stdin | --os] COMMAND
  init [--recovery] [--add-os]   create a store (passphrase from stdin or SECRETANT_PASSPHRASE)
  put NAME                       add a version; the value is read from stdin
  rotate NAME                    like put, but NAME must already exist
  get NAME [--version N]         print the value to stdout
  list                           print the names
  run NAME[,NAME] -- CMD ARGS    run CMD with each NAME as an environment variable
  cloudflare plan|apply|verify MANIFEST  set a Cloudflare Worker's secrets from the store;
                                       prints names and states, never values
  deliver plan|apply|verify MANIFEST   place values in files named by a JSON manifest;
                                       prints names and states, never values
";

/// Exit codes: 0 done, 1 refused or failed, 2 wrong usage.
fn main() -> ExitCode {
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<_, _>>()
    {
        Ok(a) => a,
        Err(_) => return usage(),
    };
    match go(args) {
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

fn usage() -> ExitCode {
    eprint!("{USAGE}");
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
    Auto,
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

fn open(path: &PathBuf, how: &How, input: &mut Input) -> Result<FileStore, Fail> {
    match how {
        How::Os => Ok(FileStore::open_with(path, Unlock::Os)?),
        How::Recovery => {
            let k = input.line()?;
            Ok(FileStore::open_with(path, Unlock::Recovery(&k))?)
        }
        How::Passphrase => {
            let p = input.line()?;
            Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
        }
        How::Auto => match std::env::var("SECRETANT_PASSPHRASE") {
            Ok(p) => {
                let p = SecretValue::from_string(p);
                Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
            }
            Err(_) => Ok(FileStore::open_with(path, Unlock::Os)?),
        },
    }
}

fn go(mut args: Vec<String>) -> Result<ExitCode, Fail> {
    let mut store: Option<PathBuf> = None;
    let mut how = How::Auto;
    let mut i = 0;
    // Global options come first.
    while i < args.len() && args[i].starts_with("--") {
        match args[i].as_str() {
            "--store" => {
                store = Some(PathBuf::from(args.get(i + 1).ok_or(Fail::Usage)?));
                i += 2;
            }
            "--passphrase-stdin" => {
                how = How::Passphrase;
                i += 1;
            }
            "--recovery-stdin" => {
                how = How::Recovery;
                i += 1;
            }
            "--os" => {
                how = How::Os;
                i += 1;
            }
            _ => return Err(Fail::Usage),
        }
    }
    args.drain(..i);
    if args.is_empty() {
        return Err(Fail::Usage);
    }
    let path = store.or_else(default_store).ok_or(Fail::Usage)?;
    let cmd = args.remove(0);
    let mut input = Input(std::io::stdin());

    match cmd.as_str() {
        "init" => {
            let mut want_recovery = false;
            let mut want_os = false;
            for a in &args {
                match a.as_str() {
                    "--recovery" => want_recovery = true,
                    "--add-os" => want_os = true,
                    _ => return Err(Fail::Usage),
                }
            }
            let pass = match how {
                How::Passphrase => input.line()?,
                How::Auto => match std::env::var("SECRETANT_PASSPHRASE") {
                    Ok(p) => SecretValue::from_string(p),
                    Err(_) => return Err(Fail::Usage),
                },
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
        "put" | "rotate" => {
            let [name] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let mut s = open(&path, &how, &mut input)?;
            if cmd == "rotate" {
                s.describe(name)?;
            }
            let value = input.rest()?;
            let v = s.put(name, value, BTreeMap::new())?;
            println!("version {v}");
            Ok(ExitCode::SUCCESS)
        }
        "get" => {
            let (name, version) = match args.as_slice() {
                [n] => (n, None),
                [n, f, v] if f == "--version" => {
                    (n, Some(v.parse::<u32>().map_err(|_| Fail::Usage)?))
                }
                _ => return Err(Fail::Usage),
            };
            let s = open(&path, &how, &mut input)?;
            let value = match version {
                Some(v) => s.get_version(name, v)?,
                None => s.get(name)?,
            };
            let mut out = std::io::stdout().lock();
            out.write_all(value.expose())
                .map_err(|_| Fail::Store(StoreError::Io))?;
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            if !args.is_empty() {
                return Err(Fail::Usage);
            }
            let s = open(&path, &how, &mut input)?;
            for n in s.list() {
                println!("{n}");
            }
            Ok(ExitCode::SUCCESS)
        }
        "run" => {
            let split = args.iter().position(|a| a == "--").ok_or(Fail::Usage)?;
            let (names, rest) = args.split_at(split);
            let command = &rest[1..];
            let [list] = names else {
                return Err(Fail::Usage);
            };
            let Some((program, program_args)) = command.split_first() else {
                return Err(Fail::Usage);
            };
            let s = open(&path, &how, &mut input)?;
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
        "cloudflare" => Err(Fail::Text(
            "this build has no Cloudflare support: build with --features cloudflare",
        )),
        #[cfg(feature = "cloudflare")]
        "cloudflare" => {
            let [mode, manifest] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let (worker, token, mappings) = read_cf_manifest(manifest)?;
            let s = open(&path, &how, &mut input)?;
            let mut ledger_name = std::ffi::OsString::from(manifest);
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
            };
            let mut bad = false;
            match mode.as_str() {
                "plan" => {
                    for (i, a) in secretant::cf::plan(&s, &ledger, &worker, &token, &mappings)
                        .map_err(cf_fail)?
                    {
                        let word = match a {
                            Action::Create => "create",
                            Action::Update => "update",
                            Action::Unchanged => "unchanged",
                        };
                        println!("{} {word}", mappings[i].0);
                    }
                }
                "apply" => {
                    let n = secretant::cf::apply(&s, &mut ledger, &worker, &token, &mappings)
                        .map_err(cf_fail)?;
                    println!("sent {n} secret(s)");
                }
                "verify" => {
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
                _ => return Err(Fail::Usage),
            }
            Ok(if bad {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        "deliver" => {
            let [mode, manifest] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let placements = read_manifest(manifest)?;
            let s = open(&path, &how, &mut input)?;
            let mut ledger_name = std::ffi::OsString::from(manifest);
            ledger_name.push(".ledger.json");
            let mut ledger = Ledger::open(PathBuf::from(ledger_name)).map_err(deliver_fail)?;
            let mut bad = false;
            match mode.as_str() {
                "plan" => {
                    for (i, a) in secretant::plan(&s, &ledger, &placements) {
                        let word = match a {
                            Action::Create => "create",
                            Action::Update => "update",
                            Action::Unchanged => "unchanged",
                        };
                        println!("{} {word}", placements[i].name);
                    }
                }
                "apply" => {
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
                "verify" => {
                    for (i, st) in secretant::verify(&s, &ledger, &placements) {
                        let word = match st {
                            State::InSync => "in-sync",
                            State::Stale => "stale",
                            State::Drifted => "drifted",
                            State::Missing => "missing",
                            State::LoosePerms => "loose-permissions",
                            State::Unreadable => "unreadable",
                        };
                        bad |= st != State::InSync;
                        println!("{} {word}", placements[i].name);
                    }
                }
                _ => return Err(Fail::Usage),
            }
            Ok(if bad {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        _ => Err(Fail::Usage),
    }
}

fn deliver_fail(e: DeliverError) -> Fail {
    match e {
        DeliverError::Store(s) => Fail::Store(s),
        DeliverError::Io => Fail::Text("a target could not be read or written"),
        DeliverError::Unsupported => Fail::Text("the value does not fit that kind of target"),
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
