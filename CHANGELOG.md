# Changelog

## [0.0.4]

- Unlock wraps (ROADMAP row 2): a recovery wrap (the recovery text is shown once and never stored readable), Windows DPAPI OS-bound wrap (unattended open as the same user; other systems get a named error), `Unlock` and `FileStore::open_with`. Several wraps open the same store; losing one still opens via another. Store file is owner-only (`0600` on Unix, ACL reduced to the current user on Windows). Not published.

## [0.0.3]

- `Store` trait and `FileStore` (ROADMAP row 1, second slice): one JSON file; random data key, XChaCha20-Poly1305; the key wrapped by an Argon2id passphrase wrap (wrap list ready for more); put/get/get_version/list/describe with versions and non-secret metadata; atomic write keeping one previous generation (`.prev`); errors carry a class and no text. Canary tests (the leak mutation is caught), every flipped ciphertext byte fails, hostile KDF costs refused. Not published.

## [0.0.2]

- `SecretValue` (ROADMAP row 1, first slice): no `Display`, `Clone` or `Serialize`; `Debug` shows nothing; wiped on drop through `redactant`. Canary tests with negative controls. Not published.

## [0.0.1]

- Design note added (`docs/DESIGN.md`): goal, who holds what, interface, stores, push versus pull, ConfigurAnt and web interface integration, installer bootstrap, threat model, build-or-adopt, order and slices, patent queries, decisions. Docs only; not published.

## [0.0.0]

- Name reserved with an empty placeholder crate (published 2026-10-22).
