# Changelog

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
