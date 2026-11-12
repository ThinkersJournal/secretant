# Publish plan: SecretAnt 0.1.0

Written 2026-11-12 by the SecretAnt lane at the PM's request. **The lane does not publish.** The PM decides the date and runs the publish and the tag.
Facts below are at `origin/main` 9404e56 plus the open PRs #11 (row 6), #13 (`SecretReader::list`), #14 (no-echo prompt) and #15 (patent sweep); each "not done" is a blocker until it is done or ruled otherwise. The PM answered the six questions of section 11 on 2026-11-12; the sections below say where each answer landed.

## 1. What 0.1.0 is

ROADMAP rows 1 to 6: `SecretValue`, the encrypted file store, three ways to open it (passphrase, recovery text, Windows user account), the read API for
adapters (`SecretReader`), the `secretant` command line, delivery to files and environment files, and Cloudflare Worker secret delivery. First release with
functionality (the crate on crates.io today is the 0.0.0 placeholder).

## 2. What `SecretValue` and the crate promise, and what they do not

Promised, each backed by a test in the repository:
- `SecretValue` has no `Display`, `Clone` or `Serialize`; `Debug` shows nothing; the bytes are wiped when it is dropped.
- The store file never holds a value, in any encoding, in the clear; every flipped ciphertext byte fails loudly; a hostile file cannot demand absurd key-derivation cost.
- Errors carry a class and never a name, value, path or file text. The command line prints a fixed sentence per class.
- The store file is private to its owner (`0600`; on Windows the ACL is reduced to the user and read back).
- A value is never a command-line argument; `list` prints names only; `run` puts values in the child's environment only and removes the unlock passphrase from it.

**Not promised (stated on the README first screen and repeated here):**
- **Same-user limit.** Any program running as the same user can do what SecretAnt's own read API does (the Windows-account wrap and a readable store file are the same boundary). SecretAnt does not defend against a hostile process of the owner.
- No recovery path of ours: lose every way of opening the store and the secrets are gone.
- Memory is wiped on drop but not locked: swap files, core dumps and hibernation may hold a value. Copies made by libraries are not wiped: values passed to a child's environment, the Cloudflare request body inside the HTTP client, and a standard `String` while a JSON body is built.
- `get` prints a value to standard output by design; what reads that output is the caller's concern.
- Delivered copies (files, Worker secrets) are derived copies: a host compromise reveals the copies on that host.

## 3. The easy gate (EXPECTATIONS 6.24)

| Step | State | Work |
|---|---|---|
| Intended hello-world first, about ten lines a stranger can copy | **not done** | README opens with the same-user limit (kept first on purpose) and then a ten-line example: create a store, put, read through `SecretReader`, and the three-line CLI equivalent |
| README examples compiled in CI | **not done** | include the README as the crate's doc (`#![doc = include_str!("../README.md")]`) so `cargo test --doc` in the existing CI job compiles and runs it; the example must use a temporary directory and a cheap key-derivation setting so CI stays fast |
| Fresh-eyes trial: an agent given only the published crate's README must reach the example's result | **not done** | run after the crate is on a registry or a local registry mirror, a fresh agent with no repository access; its transcript goes on the publish PR; a failed trial blocks the publish, and the PM weighs the transcript as advice |
| Errors say what to do next | **partly** | today an error is a class sentence (by design, no names or text). Each class sentence should add a next step without adding a name ("the passphrase did not open the store; check it, or use the recovery text"). Small change, one test per class |
| One obvious path, safe defaults, an escape hatch | **done in #14, one manual check left** | hidden-prompt passphrase entry (no echo, no argv, no environment fallback by default; `--passphrase-env`, `--passphrase-stdin`, `--recovery-stdin`, `--os` are explicit). CI has no terminal, so the PM types a passphrase once on Windows and once on Linux (WSL) before publish and records it here |

## 4. CI and branch protection (EXPECTATIONS 6.5)

At `origin/main` 9404e56 (read from `branches/main`): protected, enforcement `non_admins`, three required contexts: build/test/clippy/fmt/doc on Ubuntu and
Windows, and `cargo deny`. CodeQL runs. Open items:
- The `portfolio` (CodeRipper) job is **not** a required context and is red on every PR with one advisory finding (SEC-002, the false positive at `CHANGELOG.md:5`, a line already in `main` history; ruled a CodeRipper defect and routed to the coderipper lane). Before publish: either the coderipper fix lands and the job is green, or the PM records a ruling that 0.1.0 publishes with it red.
- **Decided (PM, 2026-11-12):** at publish `portfolio` is green or each red has a recorded ruling. The SEC-002 ruling is a waiver on CodeRipper's side, not a repository change. Record it here when written: `<ruling reference>`.
- `cargo publish --dry-run` and `cargo package --list` (nothing from `docs`, `HANDOFF.md`, `tools` that should not ship; `include`/`exclude` set in `Cargo.toml`) belong in a release job or the publish PR checklist. Not done.

## 5. Patent sweep record

**Done as far as it goes, in #15** (the lane runs it; the PM reviews the independent claims it names). Seven ideas, eleven queries, five patents read claim by claim, all clear on the independent claims read; limitations stated (general web search, not the patent databases; delivery is the least searched area). The earlier text follows for the record: `docs/PATENT-SWEEP.md` listed four techniques (several independent wraps of one random data key; a personal store with versions driving delivery; a ledger of which version was placed where so stale and drift differ without showing a value; write-only host delivery verified without reading back) and no queries run. `docs/DESIGN.md` section 13 holds the queries. A sweep (Google Patents, USPTO, Espacenet, WIPO) with dates and sources is a precondition of the first release with functionality. Not legal advice; no attorney exists. This is a PM or CireSnave step, not a lane step; the lane can run the queries and record hits if the PM asks.

## 6. Provenance and licences

- Our code is `MIT OR Apache-2.0`; `LICENSE-MIT` and `LICENSE-APACHE` are in the repository; every source file carries an SPDX header (checked by the portfolio job).
- No third-party source is copied into the repository (to re-verify at publish with `git ls-files` against the dependency list). Windows DPAPI is called through `windows-sys`.
- Dependencies: **82 packages in `Cargo.lock` after row 6 (51 before it)**; the 31 added are the TLS stack under the HTTP client for row 6 (rustls, webpki, ring and aws-lc among them). Licences (from `cargo metadata`): MIT or Apache-2.0 in all but ISC, BSD-3-Clause, CDLA-Permissive-2.0, Unicode-3.0 and a few ISC/OpenSSL-family crypto crates; all permissive, all inside `deny.toml`'s allow list, which CI enforces.
- At publish, attach `cargo deny list` output to the publish PR, and keep each dependency's own licence notice (crates.io carries them in the crate files).
- **Decided (PM, 2026-11-12): gate the HTTP client behind a cargo feature, off by default**, so a store consumer pulls no TLS stack unless the Cloudflare target is asked for, and keep the 51-package default build in CI as its own job. Planned as the next change after #11 merges (it touches the same files). The client is `minreq` (not `ureq`: at trace level `ureq-proto` hex-dumps wire bytes, token included; see #11).

## 7. The crates.io name

`secretant` 0.0.0 was published 2026-10-22 as a placeholder; `cargo owner --list secretant` shows `ciresnave`. Steps at publish (PM): confirm ownership, `cargo publish --dry-run`, publish, then the annotated tag `v0.1.0` on the exact commit with `tools/tag-release.sh` (EXPECTATIONS 6.20). The PM allocates the version number at the gate; the changelog is stamped from fragments by `tools/stamp-version.py`.

## 8. Consumers verified against the built crate before publish

Both are blockers until verified; neither is verified yet.

| Consumer | What it needs | What the lane knows now | How to verify |
|---|---|---|---|
| ConfigurAnt adapter (`configurant-secretant`, ConfigurAnt rows 4 and 25) | `SecretSource::fetch(&self, reference) -> Result<SecretValue, SourceError>` with classes NotFound, Denied, Unreachable, TimedOut | `SecretReader::get` has exactly those four classes and a timeout; the value type is SecretAnt's `SecretValue`, so the adapter converts to ConfigurAnt's redacted value | build the adapter against a local checkout of this crate with a temporary `[patch]` (never committed: crates.io-only rule), run ConfigurAnt's adapter-shaped test with a real store; record the result on the publish PR |
| WebHostAnt C7b (a source over SecretAnt's store: get by name, listing, audit) | get, list, audit | C7a already compiles against `secretant` 0.0.2's `SecretValue`. `SecretReader::list` (names only, never values) is in #13 (PM decision). There is still **no audit** (row 11, AuditAnt) | verify C7b against the built crate with a temporary `[patch]`; audit stays out of 0.1.0 unless the PM says otherwise |

## 9. The unconfirmed live-Cloudflare limit, plainly

Row 6 has **never been run against the real Cloudflare API**: the lane has no token. It follows Cloudflare's published reference (read 2026-11-12) and passes a fake-API test suite (request placement, error classes, stale/never-half-rotated, log capture). The fake encodes our reading of the documentation, so a mistake in that reading would pass the tests. CI never calls the live API.

**Decided (PM, 2026-11-12):** 0.1.0 waits for ONE live run, which the PM does (scratch Worker, dummy values), recording the result and the request ids here. If the PM cannot get a token with the right scope (`Workers Scripts Write`), the PM tells the lane and 0.1.0 ships with the limit stated (the PM's call then). Until a live run is recorded, the changelog and README say "fake-API tested only" for Cloudflare delivery.

Live run record: not done. `<date, Worker, request ids, result>`

## 10. Order of the "After v1" rows (ROADMAP rows 7 to 11)

In the order I would take them, each with its blocker:

1. **Row 7: backup, export/import bundle (dry run first), restore test, `doctor`.** Needs rows 1 and 2 (done). Blocker: none. First because a store a school cannot back up and restore is not safe to hand over, and row 8 needs it.
2. **Row 8: installer step library (`probe/plan/apply/read_back`), recovery-key confirmation, Humboldt change request.** Needs rows 2 and 7. Blocker: the Humboldt installer owner's agreement to the change request, and a decision on how the person confirms the recovery key was saved (CireSnave's words in `docs/DESIGN.md` sections 1 and 2 govern).
3. **Row 10: SecretAnt's own ConfigurAnt schema and the cycle check.** Needs row 3 (done). Blocker: ConfigurAnt's published types and the adapter (rows 4 and 25) existing; the cycle check cannot run until ConfigurAnt depends on `secretant` from crates.io.
4. **Row 9: macOS Keychain and Linux Secret Service / `systemd-creds` wraps.** Needs row 2 (done). Blocker: test environments. This machine is Windows; macOS runners exist on GitHub but a Linux Secret Service needs a D-Bus session in CI, and `systemd-creds` needs systemd. Not testable from here without that setup; a person on those systems asked for it is the trigger.
5. **Row 11: adopt RedactAnt and AuditAnt.** Blocker: those crates published. Nothing to build until then; `redactant` 0.1 is already a dependency, so check what RedactAnt's own row says before treating this as new work.

Rows 7 and 8 are the useful ones for a school. Rows 10 and 9 move only when their blocker moves.

## 11. Decisions made (PM, 2026-11-12) and where each landed

1. Gate the HTTP client behind a cargo feature, off by default, with the 51-package default build as its own CI job: **decided; to do after #11 merges** (section 6).
2. `SecretReader::list` in 0.1.0, names only, additive: **done in #13**.
3. Hidden-prompt passphrase entry before 0.1.0 (no echo, no argv, no environment fallback by default): **done in #14**; the manual terminal check is the PM's (section 3).
4. 0.1.0 waits for one live Cloudflare run by the PM, or ships with the limit stated if no token with the right scope exists: **open** (section 9).
5. `portfolio` green or a recorded ruling per red at publish; the SEC-002 ruling is a CodeRipper-side waiver: **ruling to be recorded** (section 4).
6. The lane runs the patent sweep and writes the claim readings; the PM reviews the independent claims; conservative, and says what was not searched: **done in #15**, with the delivery area flagged as least searched (section 5).

Versions are the PM's to allocate; publishing is the PM's. The lane does not publish.

- lane: secretant
