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
    Action, CloudflareError, CloudflareWorker, DeliverError, FileStore, ImportConflict, Ledger,
    Level, Placement, SecretValue, State, Store, StoreError, Target, Unlock,
};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

mod prompt;
use prompt::{Ask, AskError, Terminal};

const USAGE: &str =
    "usage: secretant [--store PATH] [--passphrase-stdin | --recovery-stdin | --os | --passphrase-env] COMMAND
  (no unlock option: the passphrase is asked on the terminal, no echo)
  init [--recovery] [--add-os]   create a store (new passphrase asked twice on the terminal)
  put NAME                       add a version; the value is asked (no echo) or read from stdin
  rotate NAME                    like put, but NAME must already exist
  get NAME [--version N]         print the value to stdout
  list                           print the names
  run NAME[,NAME] -- CMD ARGS    run CMD with each NAME as an environment variable
  backup DEST                    copy the store file (ciphertext) to DEST; needs no unlock
  restore-test BACKUP            open BACKUP and decrypt every version; prints counts
  restore BACKUP [--replace]     put BACKUP in place of the store (the old file is kept as .prev)
  doctor [--header-only]         check the store file; --header-only skips unlocking
  export BUNDLE [--bundle-passphrase-stdin]
                                 write every entry to a new store file under its own passphrase
  import BUNDLE [--apply] [--conflict keep|replace] [--bundle-passphrase-stdin]
                                 show what an import would do; --apply does it (nothing is deleted)
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
    match go(args, &mut Terminal) {
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
            let p = input.line()?;
            Ok(FileStore::open_with(path, Unlock::Passphrase(&p))?)
        }
        How::Env => {
            let p = std::env::var("SECRETANT_PASSPHRASE")
                .map_err(|_| Fail::Text("SECRETANT_PASSPHRASE is not set"))?;
            let p = SecretValue::from_string(p);
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
            let p = input.line()?;
            f(Unlock::Passphrase(&p))
        }
        How::Env => {
            let p = std::env::var("SECRETANT_PASSPHRASE")
                .map_err(|_| Fail::Text("SECRETANT_PASSPHRASE is not set"))?;
            let p = SecretValue::from_string(p);
            f(Unlock::Passphrase(&p))
        }
        How::Prompt => {
            let p = prompt::passphrase(ask).map_err(ask_fail)?;
            f(Unlock::Passphrase(&p))
        }
    };
    Ok(r?)
}

/// The passphrase of a bundle: asked on the terminal (twice when new), or the
/// next line of standard input with `--bundle-passphrase-stdin`.
fn bundle_passphrase(
    from_stdin: bool,
    new: bool,
    input: &mut Input,
    ask: &mut dyn Ask,
) -> Result<SecretValue, Fail> {
    if from_stdin {
        return input.line();
    }
    if new {
        prompt::new_bundle_passphrase(ask).map_err(ask_fail)
    } else {
        prompt::bundle_passphrase(ask).map_err(ask_fail)
    }
}

fn go(mut args: Vec<String>, ask: &mut dyn Ask) -> Result<ExitCode, Fail> {
    let mut store: Option<PathBuf> = None;
    let mut how = How::Prompt;
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
            "--passphrase-env" => {
                how = How::Env;
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
                How::Env => SecretValue::from_string(
                    std::env::var("SECRETANT_PASSPHRASE")
                        .map_err(|_| Fail::Text("SECRETANT_PASSPHRASE is not set"))?,
                ),
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
        "put" | "rotate" => {
            let [name] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let mut s = open(&path, &how, &mut input, ask)?;
            if cmd == "rotate" {
                s.describe(name)?;
            }
            let value = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                ask.secret("Value: ").map_err(ask_fail)?
            } else {
                input.rest()?
            };
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
            let s = open(&path, &how, &mut input, ask)?;
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
            let s = open(&path, &how, &mut input, ask)?;
            for n in s.list() {
                println!("{n}");
            }
            Ok(ExitCode::SUCCESS)
        }
        "backup" => {
            let [dest] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            secretant::backup(&path, std::path::Path::new(dest))?;
            println!("backup written");
            Ok(ExitCode::SUCCESS)
        }
        "restore-test" => {
            let [backup] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let sum = with_unlock(&how, &mut input, ask, |u| {
                secretant::check_backup(std::path::Path::new(backup), u)
            })?;
            println!(
                "backup opens: {} entries, {} versions",
                sum.entries, sum.versions
            );
            Ok(ExitCode::SUCCESS)
        }
        "restore" => {
            let (backup, replace) = match args.as_slice() {
                [b] => (b, false),
                [b, f] if f == "--replace" => (b, true),
                _ => return Err(Fail::Usage),
            };
            let sum = with_unlock(&how, &mut input, ask, |u| {
                secretant::restore(std::path::Path::new(backup), &path, u, replace)
            })?;
            println!(
                "restored: {} entries, {} versions",
                sum.entries, sum.versions
            );
            Ok(ExitCode::SUCCESS)
        }
        "doctor" => {
            let header_only = match args.as_slice() {
                [] => false,
                [f] if f == "--header-only" => true,
                _ => return Err(Fail::Usage),
            };
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
        "export" => {
            let mut from_stdin = false;
            let mut dest = None;
            for a in &args {
                match a.as_str() {
                    "--bundle-passphrase-stdin" => from_stdin = true,
                    _ if dest.is_none() => dest = Some(a),
                    _ => return Err(Fail::Usage),
                }
            }
            let dest = dest.ok_or(Fail::Usage)?;
            let s = open(&path, &how, &mut input, ask)?;
            let bp = bundle_passphrase(from_stdin, true, &mut input, ask)?;
            let mut bundle = FileStore::create(std::path::Path::new(dest), &bp)?;
            s.export_to(&mut bundle)?;
            println!("exported {} entries", s.list().len());
            Ok(ExitCode::SUCCESS)
        }
        "import" => {
            let mut from_stdin = false;
            let mut apply = false;
            let mut conflict = ImportConflict::Refuse;
            let mut src = None;
            let mut it = args.iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--bundle-passphrase-stdin" => from_stdin = true,
                    "--apply" => apply = true,
                    "--conflict" => {
                        conflict = match it.next().map(String::as_str) {
                            Some("keep") => ImportConflict::Keep,
                            Some("replace") => ImportConflict::Replace,
                            _ => return Err(Fail::Usage),
                        };
                    }
                    _ if src.is_none() => src = Some(a),
                    _ => return Err(Fail::Usage),
                }
            }
            let src = src.ok_or(Fail::Usage)?;
            let mut s = open(&path, &how, &mut input, ask)?;
            let bp = bundle_passphrase(from_stdin, false, &mut input, ask)?;
            let bundle = FileStore::open_with(std::path::Path::new(src), Unlock::Passphrase(&bp))?;
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
        "cloudflare" => {
            let [mode, manifest] = args.as_slice() else {
                return Err(Fail::Usage);
            };
            let (worker, token, mappings) = read_cf_manifest(manifest)?;
            let s = open(&path, &how, &mut input, ask)?;
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
            let s = open(&path, &how, &mut input, ask)?;
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

#[derive(serde::Deserialize)]
struct CfManifest {
    account_id: String,
    script: String,
    token: String,
    secrets: Vec<CfEntry>,
}

#[derive(serde::Deserialize)]
struct CfEntry {
    name: String,
    var: String,
}

type CfPlan = (CloudflareWorker, String, Vec<(String, String)>);

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
