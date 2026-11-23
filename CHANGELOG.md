# Changelog

## [0.2.4] — README and help text match the CLI (claim-to-command audit)

Every command the README and `docs/DESIGN.md` show was run against `target/debug/secretant` built at `287e5ed` (0.2.3): `init`, `put`, `get` (with `--version`), `rotate` (and its refusal of a missing name), `list`, `run` (one and two names; the child sees no `SECRETANT_PASSPHRASE`), `backup`, `restore-test`, `restore` (refused without `--replace`), `doctor` (and `--header-only`), `export`, `import` (dry run, refused conflict, `--conflict replace`), `deliver plan|apply|verify` (including a drifted file), `--os` and `init --add-os` on Windows, wrong passphrase and wrong recovery key, and no-terminal refusals. `cloudflare` was read, not run (no live service). The no-echo prompt and the macOS and Linux paths were read, not run. Fixes: `--os` help said Windows only; `restore` help did not say `--replace` is needed over an existing store; the README's version paragraph described 0.2.1 only and now names 0.2.2 and 0.2.3. The 50-package default tree was re-measured (50, no HTTP or TLS crate; 4 with `cloudflare`).

— lane: secretant

## [0.2.3] — Linux falls back to a per-user systemd-creds OS wrap (row 9 slice 3)

With the `os-keystore` feature on Linux, `FileStore::add_os_wrap` now tries the Secret Service first and, if that fails, a per-user `systemd-creds` credential (`systemd-creds --user encrypt`, needs systemd 256 or newer). The wrap kind is `os-systemd-creds`; `Unlock::Os` opens it. The data key goes to `systemd-creds` over stdin and comes back over stdout, never through argv or a file. `src/store.rs::systemd_creds_wrap_round_trips_and_a_damaged_blob_does_not_open` runs in the `systemd-creds` job of `.github/workflows/os-store-probe.yml` on ubuntu-latest with `SECRETANT_SYSTEMD_CREDS_REQUIRED=1`; elsewhere it skips loudly. `docs/FORMAT.md` lists the `os-keystore` and `os-systemd-creds` kinds.

## [0.2.2] — the installer and command line offer the OS wrap on macOS and Linux (row 9 slice 2)

`secretant::OS_WRAP_SUPPORTED` says whether this build can make an OS-bound wrap (Windows always; macOS and Linux with the `os-keystore` feature). `installer::plan_store` refuses an OS wrap only where it is false, instead of everywhere but Windows, so `secretant init --add-os`, `--os` and the installer's `os_wrap` work on a Keychain or Secret Service. `tests/installer.rs::the_os_bound_wrap_is_added_when_asked` runs on Windows and, in `.github/workflows/os-store-probe.yml`, on macos-latest and ubuntu-latest with `SECRETANT_OS_WRAP_REQUIRED=1`; elsewhere it skips loudly. The README now states the 0.2.0 Breaking change (minimum Rust 1.95) and the `os-keystore` feature. The `systemd-creds` wrap is not started. README claim-to-command audit (run at this commit): the `put`, `list` and `run` lines were executed and print what the README says; the README now shows the `SECRETANT_PASSPHRASE` export that `--passphrase-env` needs, no longer says OS wraps are Windows-only, and says "any 0.x release" instead of "0.2". The README's `--help` command list matches `secretant --help`; the 50-package count was re-measured (50).
 LICENSE-APACHE now carries the canonical Apache License 2.0 text (the earlier copy was not text-identical); the licence is unchanged: MIT OR Apache-2.0.

## [0.2.1] — EasyAnts card and a runnable quickstart example

Adds `easyants-card.toml` (status `ready`, read by the EasyAnts hub per its `docs/CARD-FORMAT.md` @12844fd) and `examples/quickstart.rs`, the seven-line excerpt the card shows: create a store, put a secret, read it back through `SecretReader`, assert the value. Cargo builds it with `--all-targets` in CI and it was run locally (exits 0). The card makes no claim about the macOS and Linux key wraps. No library change.

## [0.2.0] — **BREAKING**: minimum Rust version 1.95; own ConfigurAnt schema and cycle check (row 10); macOS Keychain and Linux Secret Service key wraps (row 9 slice 1)

Adds `configurant.toml`, SecretAnt's own ConfigurAnt schema, for the two settings that exist today: `store.path` (`SECRETANT_STORE`, `--store`) and the secret `unlock.passphrase` (`SECRETANT_PASSPHRASE`). `tests/own_schema.rs` parses it with `configurant` 0.7.2 (a dev-dependency from crates.io), refuses any `source = "secretant:..."` entry (SecretAnt must not ask itself for the key it starts with, `docs/DESIGN.md` section 6.3) with a negative control that the check fires, and checks a canary passphrase appears neither in the help text nor in the loaded configuration's `Debug`, with a positive control that it was supplied. `tools/stamp-extra.txt` keeps the schema's `version` current at stamping. No runtime change. The minimum Rust version rises from 1.88 to 1.95 because `configurant` 0.7.2 requires it (permitted by CireSnave 2026-10-08); the CI job "Builds on the declared minimum Rust version" reads it from `Cargo.toml` and checks it. New off-by-default feature `os-keystore`: `FileStore::add_os_wrap` and `Unlock::Os` now work on macOS (Keychain) and Linux (Secret Service, via the `dbus-secret-service-keyring-store` crate, with libdbus built in) as well as Windows (DPAPI). The store file holds only a random item name (wrap kind `os-keystore`); the data key lives in the OS store. Tested in `.github/workflows/os-store-probe.yml` on a real Keychain and gnome-keyring (`SECRETANT_OS_WRAP_REQUIRED=1` makes a missing key store a failure there; elsewhere the test skips loudly). The zbus-based store was rejected: it pulls RUSTSEC-2026-0371 (`zbus_names`, `zvariant` unmaintained) into `cargo deny`.

## [0.1.6] — CI: portfolio job re-pinned to coderipper 0.47.13

The portfolio workflow in `.github/workflows/ci.yml` now points at coderipper 0.47.13, whose reviewed SEC-002 waivers cover the two history findings in `CHANGELOG.md`. No code change. Checked by the Portfolio job on this PR.

— lane: secretant

## [0.1.5] — Changed

README no longer names a release number in its status line or headings, and its known-gaps list says the hidden-prompt (no echo) entry is not tested through a real terminal on Windows or WSL. `.coderipper.toml` declares the volatile names (`minreq`, `crate::cloudflare`) and the composition root (`src/main.rs`), and says `none` for an API budget, owned data and pure components, each with the reason read from the code, so ARC-003, ARC-006, ARC-007, ARC-012 and EFX-001 run instead of reading "not run". One CHANGELOG line for 0.0.3 is reworded so the secret scanner stops matching it in the current tree. Checked by running those five rules with coderipper 0.47.13 (0 findings, all ran) and gitleaks 8.30.1 in dir mode (0 findings). No code change.

## [0.1.4] — Changed

HANDOFF.md rewritten to current state (no code change).

## [0.1.3] — Changed

ROADMAP.md status now matches the forge (rows 1 to 8 merged, 9 to 11 blocked, with the reason). New test `a_truncated_backup_or_bundle_fails_loudly_and_changes_nothing` in tests/cli.rs: a backup or export bundle cut to 0, 1, half and all-but-one bytes fails `restore-test`, `restore` and `import --apply` with exit 1, prints no canary and leaves the store byte-identical (it passed on first run, so it guards the behaviour rather than fixing a bug).

## [0.1.2] — Changed

The command line names where a bundle passphrase comes from with a small enum instead of two `bool` parameters (TYP-007); behaviour is unchanged and the existing `tests/cli.rs` bundle tests cover both paths. `tools/fresh-eyes-trial.sh` carries an SPDX line (SUP-016).

## [0.1.1] — Changed

CI: the Portfolio job moves to CodeRipper 0.47.5 (workflow `c72a6e0`). The rule-id migration found nothing to rename (`.coderipper.toml` already uses numbered ids). No code change.

## [0.1.0] — **BREAKING**: first release with functionality

The first SecretAnt release that does anything. **Breaking** relative to the 0.0.x placeholder line: the public error, state and outcome enums are `#[non_exhaustive]` (a `match` on one needs a wildcard arm).

- `SecretValue` (no `Display`, `Clone` or `Serialize`; `Debug` shows nothing; wiped on drop), `FileStore` (XChaCha20-Poly1305 under a random data key; passphrase (Argon2id), recovery-key and Windows user-account wraps open the same key; atomic writes with one previous generation; owner-only file), `SecretReader` (open, get, list; four error classes and a timeout on every call).
- Backup, restore, restore-test, `doctor`, export and import bundles; delivery plan, apply and verify to files and environment files with a ledger; the `secretant` command line (clap).
- The installer step library (`installer`, `secrets_step`, `place_step`), pre-1.0: may change in 0.2.
- Cloudflare Worker delivery behind the off-by-default `cloudflare` feature: tested against a fake of the documented API only, **not run against the live service**. The default build has 50 packages and no HTTP or TLS crate.
- Not in 0.1.0: audit, macOS and Linux OS-bound wraps, a web interface, remote vaults. See the README.
- Minimum Rust version 1.88, checked in CI. A new developer gets from `cargo add` to the README example in under a minute (fresh-eyes trial, 35 s on 0.0.36).

## [0.0.38] — Changed

README: the ten-line example now shows its `cargo add tempfile` step and what the hidden lines are, and explains the `Features: - cloudflare` line `cargo add` prints. Rustdoc no longer cites ROADMAP rows or `docs/INSTALLER-STEPS.md`. Found by the first fresh-eyes trial; verified by a second.

## [0.0.37] — Added

`tools/fresh-eyes-trial.sh`: sets up the fresh-eyes trial (EXPECTATIONS 6.24). It builds the crate as `cargo package` ships it, makes a fresh project with only the README and rustdoc, prints the brief and times the run; `finish` runs the result. First run (0.0.36, blind Sonnet agent): PASS, one stumble, reported separately.

## [0.0.36] — CI builds on the declared minimum Rust version

New CI job "Builds on the declared minimum Rust version": it reads `rust-version` from `Cargo.toml` (so the promise and the check cannot drift), installs that toolchain and runs `cargo check --locked --all-targets` with default features and with all features; it fails if `Cargo.toml` declares none. No code change. Verified locally on 1.88.0 (both checks pass).

## [0.0.35] — **BREAKING**: 0.1.0 candidate: public enums are non_exhaustive, README and package metadata

Ready for the 0.1.0 publish (list reviewed by the PM). **Breaking:** the public error, state and outcome enums (`StoreError`, `ReadError`, `DeliverError`, `CloudflareError`, `InstallError`, `PlaceError`, `CloudflarePlaceError`, `SecretsError`, `State`, `Action`, `StoreProbe`, `StoreAction`, `StoreApplied`, `SecretAction`, `Level`, `Check`, `Encoding`, `ImportConflict`) are `#[non_exhaustive]`, so a variant added later is not a breaking change; a `match` on one needs a wildcard arm (the command line's own matches have them). Package: the description no longer says "Placeholder"; keywords, categories, `rust-version = "1.88"` (the newest of the dependencies' declared minimums; the crate builds on 1.88.0), docs.rs builds with all features, and `exclude` keeps the lane's own files (`HANDOFF.md`, `ROADMAP.md`, `tools/`, `.github/`, the Humboldt change request, the publish plan, the patent sweep) out of the crate. README: same-user limit first, then a ten-line example that is compiled and run as the crate's doc test, the command-line equivalent, what is in 0.1.0, and that Cloudflare delivery is tested against a fake of the documented API only and has not been run live; the installer modules are stated as pre-1.0 and may change in 0.2. Every `StoreError` and `ReadError` sentence now says what to do next without naming anything (test per class). The dependency count in the README is corrected to 50.

## [0.0.34] — architecture declared for the ARC checks

`.coderipper.toml` declares secretant's architecture (module groups foundation, services, cloudflare, place, cli in four layers) so the ARC checks run instead of reporting "not run"; the code already obeys it (ARC-001 judged 6 edges, ARC-002 found 0 cycles, ARC-005 reported 0). The ARC-009 surface finding (growth since the 0.0.2 skeleton) and the five MOD-008 pass-through Info findings are waived with their reasons: the installer step contract's four calls, and the platform facade. Cargo.lock is updated to the newest compatible versions (cc, const-oid, errno, rustls-webpki; the dependency-freshness findings). No code changes.

## [0.0.33] — command-line basics (clap), tests use what they call

The `secretant` command line is parsed by `clap` (CodeRipper OPS-012) instead of by hand: `--help` and `-h` (also per command) print the help and exit 0, `--version` and `-V` print `secretant VERSION` and exit 0 (OPS-011); a missing command, an unknown flag or command, or a stray argument exits 2 with one fixed sentence that never echoes what was typed (a value given as an argument is still refused and never shown). Unlock options may now come anywhere on the line; if several are given, `--passphrase-stdin`, `--recovery-stdin`, `--os`, `--passphrase-env` win in that order. Commands, arguments, output and exit codes are otherwise as before, checked by the existing `tests/cli.rs` and a new test for help, version and the fixed usage sentence. The tests in `deliver.rs` and `store.rs` that called `apply` and `new_store` and dropped the result now check it (the two unused-return-values findings). Adds the dependency `clap` (no default features; no network or TLS code).

## [0.0.32] — installer worked example and plain-words constant

`secretant::installer::PLAIN_WORDS` and `plain_words(protection)`: the text of DESIGN 8.2 the installer shows before first use. `docs/INSTALLER-EXAMPLE.md` is the worked example; `tests/installer_example.rs` runs it end to end (store, recovery confirmation, secrets, place; a second run changes no file; no secret in anything shown, with a control) and checks the plain words against DESIGN 8.2 word for word and the document against the calls it names.

## [0.0.31] — installer Place step for a Cloudflare Worker

New submodule `secretant::place_step::cloudflare` (feature `cloudflare`), row 8b completed: `probe_cloudflare`, `plan_cloudflare`, `apply_cloudflare`, `read_back_cloudflare`, the same four calls and fingerprint as the file Place step over `cf::plan/apply/verify`. A plan carries the probe it was made from, so `apply_cloudflare` refuses (and sends nothing) if the Worker's secrets or the store changed since; a no-op plan sends no request; all secrets go in one request and the ledger is written only after Cloudflare accepts it. Worker secrets are write-only, so the read-back says unset, stale or current by the ledger, never a value. Plans, reports and errors carry names, indexes, counts and classes only. Verified by `tests/place_cloudflare.rs` against the fake API (value only in the one write body and absent from every plan, report and read-back, with a control; no-op sends nothing; rotation sends only what changed; stale plan; refused token; rejected write leaves the ledger alone). Not published; no live Cloudflare run yet.

## [0.0.30] — installer Place step for files and environment files

New module `secretant::place_step`, row 8b (second half), designed in `docs/INSTALLER-STEPS.md` 4.3: `probe_place`, `plan_place`, `apply_place`, `read_back_place`, a thin step over `deliver` in the same four calls as the Store and Secrets steps. A plan carries the probe it was made from, so `apply_place` refuses (and writes nothing) if a target or the store changed since; a placement that needs nothing is not written (a re-run touches no file); a failing placement leaves its target as it was and the others go on. Plans, reports and read-backs carry names, indexes, versions and classes only. Verified by `tests/place_step.rs` (placed value absent from every plan, report and read-back, with a control; no-op; new version updates only what changed; stale plan; one failure) and two mutations (skip the stale-plan check, write unchanged targets) that each failed a test. Not published.

## [0.0.29] — installer Store step (probe, plan, apply, read_back)

New module `secretant::installer`, row 8a, designed in `docs/INSTALLER-STEPS.md`: `probe_store`, `plan_store`, `apply_store`, `confirm_recovery`, `discard_pending`, `read_back_store`. A new store is written at `PATH.pending` with a passphrase wrap, a recovery wrap and, where asked on Windows, an OS-bound wrap; the recovery key is returned once and the file becomes the store only after `confirm_recovery` opens it with the key the person typed back, so a crash never leaves a store whose key nobody confirmed. An existing store is used and never duplicated; a plan is refused if the situation changed since it was made; an empty passphrase, a damaged file and an OS wrap on a system without one are refused and nothing is written; the library never asks, prints or logs. Verified by `tests/installer.rs` (key and passphrase absent from the pending and final files in plain, bare, upper, lower, hex, base64 and UTF-16 forms with a planted-text control; interruption, stale plan, existing store byte-for-byte) and two mutations (skip the typed-back check, skip the stale-plan check) that each failed a test. Not published.

## [0.0.28] — second passphrase wrap and wrap removal

A store can now have a second holder: `FileStore::add_passphrase_wrap` adds another passphrase with its own salt that opens the same store while the first keeps working (an empty one is refused, and so is one that already opens the store), and `FileStore::remove_wrap(index)` removes one way of opening it (the last cannot be removed). Removal is not revocation, and says so in its doc comment, in `docs/FORMAT.md` and in a test: the data key is unchanged, so an older copy of the file still opens with the removed holder's passphrase; replace the secrets that person could read. New error classes `DuplicateWrap` and `LastWrap`. This is the library part of ROADMAP row 8 (the second holder asked for schools by decision D6); the installer steps follow after the Humboldt answer. Verified by four tests in `src/store.rs` (both holders open; the second passphrase is in the file in no form, with a planted-text control; empty and duplicate leave the file unchanged; removed wraps stop opening, the last is refused), and two mutations (drop the last-wrap check, drop the duplicate check) each failed a test. Removal also rewrites the `.prev` generation without the removed wrap (found in review: `.prev` would otherwise still open with the removed passphrase), tested and mutation-checked. Not published.

## [0.0.27] — row 8 design: installer step library API and Humboldt change request (docs only)

Two design documents and the rulings they rest on, no code. `docs/INSTALLER-STEPS.md` designs the installer step library (`probe`, `plan`, `apply`, `read_back` for the Store, Secrets and Place steps, plan fingerprints, creating a store with the recovery key shown once and confirmed by typing it back, a second holder for schools, an existing store never duplicated, tests written first); `docs/HUMBOLDT-CHANGE-REQUEST.md` asks the Humboldt installer owner to agree, amend or decline eight changes. `ROADMAP.md` and `docs/PUBLISH-0.1.0.md` now record D4 = A and D6 = A (board 319) and D3 = A and D5 = A (board 400) as ruled, so only the Humboldt owner's agreement blocks row 8. Facts about the Humboldt installer are from its design note at its `origin/main`; what it does not say is marked UNVERIFIED. Not published.

## [0.0.26] — installer Secrets step (probe, plan, apply, read_back)

New module `secretant::secrets_step`, row 8b (first half), designed in `docs/INSTALLER-STEPS.md` 4.2: `probe_secrets`, `plan_secrets`, `apply_secrets`, `read_back_secrets`, and `FileStore::put_many` (several new versions, one atomic write, rolled back on failure). A name is given by the caller or generated by the library (N random bytes as standard padded base64 or hex; `TOTP_ENCRYPTION_KEY` is 32 bytes, 44 characters) and a generated value is never returned. A name already in the store is kept unless a rotation is asked, so a re-run writes nothing (file byte-for-byte unchanged); a rotation adds a version and deletes nothing; a plan is refused if the store changed since it was made; empty values, zero lengths, duplicate and bad names are refused before anything is written. Plans, reports and errors carry names, versions and classes only. Verified by `tests/secrets_step.rs` (typed and generated values absent from plan, report, error text and the store file, with a planted-text control; keep-by-default; one write) and two mutations (skip the stale-plan check, make Keep add a version) that each failed a test. The Place step (deliver and Cloudflare wrapped in the same four calls) follows as its own PR. Not published.

## [0.0.22] — HTTP client behind a cargo feature (off by default)

Cloudflare Worker delivery and its HTTP client (`minreq`, with the TLS stack under it) are now behind the cargo feature `cloudflare`, off by default: a consumer of the store pulls no HTTP or TLS crate (the default build is 44 packages in the normal dependency tree, with no HTTP client, TLS or OpenSSL crate in it). Building with the `cloudflare` feature adds `secretant::cf`, the `CloudflareWorker` types and the `cloudflare` command; without the feature that command says so. CI: a new job (`Default build has no HTTP or TLS stack`) fails if the default tree contains any of those crates and checks the feature does bring them in (negative control); the build and test job now also tests and lints with all features. The Cloudflare tests require the feature. Not published.

## [0.0.21] — backup, restore-test, restore, doctor, export, import commands

The command line gains the row 7 commands. `secretant backup DEST` copies the store file as it is (ciphertext, owner-only, never over an existing file) and needs no unlock; `restore-test BACKUP` opens it and decrypts every version, printing counts only; `restore BACKUP [--replace]` checks the backup first, refuses to replace a store unless asked and keeps the old file as `.prev`; `doctor [--header-only]` prints fixed-sentence findings (no name, no path) and exits 1 on a failure; `export BUNDLE` writes every entry and version to a new store file under its own passphrase (asked twice, or `--bundle-passphrase-stdin`); `import BUNDLE` is a dry run listing names and version counts, and `--apply` imports, with `--conflict keep|replace` for names already present (without a choice a conflict refuses and writes nothing; nothing is ever deleted). Verified by `tests/cli.rs`: the backup and the bundle are searched for the recovery key, passphrase and value in plain, bare, upper, lower, hex, base64 and UTF-16 forms (with a planted-text control); a backup that leaks the passphrase and a restore that skips the replace check were each made and each failed a test. An empty passphrase is refused by `init`, every unlock and a new bundle (`StoreError::EmptyPassphrase`, also checked in `FileStore::create`). Not published.

## [0.0.19] — Patent sweep record (docs)

`docs/PATENT-SWEEP.md` now holds the first patent sweep for the 0.1.0 candidate: seven ideas, eleven queries (general web search, not the patent databases), five patents read claim by claim (US10536272B2, US11502833B2, US11057210B1, US10148437B2, US12463959B2), all clear on the independent claims read, and a limitations section stating what was not searched. Delivery (ideas 3 to 5) is flagged as the least searched area. Not legal advice. Docs only; not published.

## [0.0.18] — **BREAKING**: the command line asks for the passphrase without echo

The `secretant` command line no longer reads `SECRETANT_PASSPHRASE` by default. With no unlock option the passphrase is asked on the terminal with echo off (`init` asks twice and refuses a mismatch or an empty one; `put` and `rotate` also ask the value that way when standard input is a terminal). With no terminal there is no silent fallback: the error names the explicit options. `--passphrase-env` (the old variable, only when named) and `--passphrase-stdin`, `--recovery-stdin`, `--os` remain. The prompt goes to standard error and the answer is read from the terminal itself. Adds the `rpassword` dependency. Logic tested with a scripted terminal (`src/prompt.rs`) and the binary tests (no terminal and no option: refused, nothing created, the variable ignored; a mutation that restores the environment fallback fails it). Echo suppression itself is `rpassword`'s and is not asserted in CI. Not published.

## [0.0.16] — Publish plan for 0.1.0 (docs)

Adds `docs/PUBLISH-0.1.0.md`: what 0.1.0 contains and promises, the easy-gate, CI and protection, patent sweep, provenance and licences, name claim, consumer verification (ConfigurAnt adapter, WebHostAnt C7b), the unconfirmed live-Cloudflare limit, the order of ROADMAP rows 7 to 11 with blockers, and six decisions for the PM. Docs only; not published.

## [0.0.17] — SecretReader::list (names only)

Adds `SecretReader::list`: every name in the store, sorted, for adapters that list (WebHostAnt C7b). Names only: the call never reads a value; it is bounded by the same timeout, reads the file afresh, and fails with the same classes as `get`. Additive. Test with a negative control (the value is in the store and `get` returns it, but nothing `list` returns holds it); a mutation that appends values to the names fails it. Not published.

## [0.0.15] — Row 5: delivery plan, apply and verify

Deliver stored secrets to owner-only files and environment files (`src/deliver.rs`, `secretant deliver plan|apply|verify MANIFEST`). `plan` writes nothing; `apply` writes each target atomically and records which version went where in a ledger of names, paths and numbers; `verify` reports in-sync, stale (an older version we placed), drifted (hand edit), missing or loose permissions, and a report never holds a value. A failed target keeps its old content and stays stale. Tests: `src/deliver.rs` (7) and `tests/cli.rs`; two mutations (ledger written before the file, file created without owner-only permissions) each fail tests. Not published.

Place stored secrets as Cloudflare Worker secrets (`src/cloudflare.rs`, `secretant cloudflare plan|apply|verify MANIFEST`), written against Cloudflare's published API (2026-11-12): a preflight list of secret names proves the stored API token before any value is sent, then one bulk request (one new Worker version, all or nothing) carries the values; the ledger is updated only after Cloudflare accepts it. Worker secrets are write-only, so `verify` says set, unset or stale, not that a value matches. The token appears only in the Authorization header and values only in the request body; errors are classes (denied, not found, rate limited, unreachable, timed out, rejected) and never carry response text. Fake-API tests in `tests/cloudflare.rs` (7) and a log-capture test in `tests/cloudflare_logs.rs` (neither the token nor a value appears in any log line at trace level or in any error text, with a negative control); three mutations (ledger recorded before the write, token placed in the URL, token logged) each fail tests. Adds the `minreq` dependency (a blocking client that logs no request or response bytes). Not published.

Library side of ROADMAP row 7 (`src/maintain.rs`, additions in `src/store.rs`, format in `docs/FORMAT.md`). `backup` copies the store as it is (ciphertext, no key, owner-only, never overwrites); `check_backup` opens it and decrypts every version, so a backup with a flipped byte fails loudly; `restore` refuses a backup that does not open and replaces a store only when asked, keeping the old file as `.prev`; `doctor` reads the plain header and the file (and the whole store if given an unlock) and reports findings in fixed sentences with no name, value or path (one way to open the store, no recovery key, passphrase cost below the Argon2id floor, loose permissions, leftover temporary file, damaged previous generation). `FileStore::export_to` writes a bundle that is a store file under its own passphrase; `plan_import` writes nothing; `apply_import` adds new names with all their versions, and for a name already there refuses (default, nothing written), keeps, or adds the bundle's latest as a new version; nothing is ever deleted or overwritten. 6 tests; three mutations (restore without the check, import that does not refuse, doctor that always sees a recovery wrap) each fail one. The command-line commands follow once the prompt change (#14) lands. Not published.

## [0.0.7] — Row 4: the secretant command line

The `secretant` program (`src/main.rs`): `init` (optional recovery key shown once, optional Windows account wrap), `put`, `rotate`, `get` (optionally one version), `list` and `run NAME[,NAME] -- command`. A value is read from standard input and is never an argument, `list` prints names only, errors name a class and nothing else, and `run` gives the child the values in its environment only and removes the unlock passphrase from it. Canary tests in `tests/cli.rs`; two mutations (the passphrase left in the child environment, `list` printing values) each fail a test. Not published.

## [0.0.6]

- Changelog fragments and version stamping adopted: later PRs add one `changelog.d/<topic>.md` fragment and no version edit (`tools/stamp-version.py`, `tools/check-fragment.py`, workflow `.github/workflows/changelog-fragment.yml`). Dry run lists `Cargo.toml`, `Cargo.lock` and `CHANGELOG.md`; a real stamp on a scratch copy leaves no old version in any `Cargo.toml` or `Cargo.lock`. Not published.

## [0.0.5]

- Row 3: `SecretReader` for adapters. Open once with a config, then read by name. Failures are one of four classes (not found, denied, unreachable, timed out) and carry no store text. Every call is bounded by a timeout and nothing is cached: each read opens the file afresh. Not published.

## [0.0.4]

- Row 2: two more ways to open the store, a recovery text shown once (never stored readable) and the Windows user account (other systems get a named error). Any one opens the store; losing one still leaves another. The store file is readable by its owner only. Not published.

## [0.0.3]

- `Store` trait and `FileStore` (ROADMAP row 1, second slice): one JSON file; XChaCha20-Poly1305 encryption under a random data key, which is wrapped by an Argon2id passphrase wrap (wrap list ready for more); put/get/get_version/list/describe with versions and non-secret metadata; atomic write keeping one previous generation (`.prev`); errors carry a class and no text. Canary tests (the leak mutation is caught), every flipped ciphertext byte fails, hostile KDF costs refused. Not published.

## [0.0.2]

- `SecretValue` (ROADMAP row 1, first slice): no `Display`, `Clone` or `Serialize`; `Debug` shows nothing; wiped on drop through `redactant`. Canary tests with negative controls. Not published.

## [0.0.1]

- Design note added (`docs/DESIGN.md`): goal, who holds what, interface, stores, push versus pull, ConfigurAnt and web interface integration, installer bootstrap, threat model, build-or-adopt, order and slices, patent queries, decisions. Docs only; not published.

## [0.0.0]

- Name reserved with an empty placeholder crate (published 2026-10-22).
