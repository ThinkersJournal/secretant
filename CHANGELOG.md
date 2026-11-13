# Changelog

## [0.0.20] — HTTP client behind a cargo feature (off by default)

Cloudflare Worker delivery and its HTTP client (`minreq`, with the TLS stack under it) are now behind the cargo feature `cloudflare`, off by default: a consumer of the store pulls no HTTP or TLS crate (the default build is 44 packages in the normal dependency tree, none of `minreq`, `rustls`, `ring`, `aws-lc-*`, `webpki*`, `openssl`). `cargo install secretant --features cloudflare` (or `cargo build --features cloudflare`) adds `secretant::cf`, the `CloudflareWorker` types and the `secretant cloudflare` command; without the feature that command says so. CI: a new job (`Default build has no HTTP or TLS stack`) fails if the default tree contains any of those crates and checks the feature does bring them in (negative control); the build and test job now also tests and lints with all features. The Cloudflare tests require the feature. Not published.

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

- `Store` trait and `FileStore` (ROADMAP row 1, second slice): one JSON file; random data key, XChaCha20-Poly1305; the key wrapped by an Argon2id passphrase wrap (wrap list ready for more); put/get/get_version/list/describe with versions and non-secret metadata; atomic write keeping one previous generation (`.prev`); errors carry a class and no text. Canary tests (the leak mutation is caught), every flipped ciphertext byte fails, hostile KDF costs refused. Not published.

## [0.0.2]

- `SecretValue` (ROADMAP row 1, first slice): no `Display`, `Clone` or `Serialize`; `Debug` shows nothing; wiped on drop through `redactant`. Canary tests with negative controls. Not published.

## [0.0.1]

- Design note added (`docs/DESIGN.md`): goal, who holds what, interface, stores, push versus pull, ConfigurAnt and web interface integration, installer bootstrap, threat model, build-or-adopt, order and slices, patent queries, decisions. Docs only; not published.

## [0.0.0]

- Name reserved with an empty placeholder crate (published 2026-10-22).
