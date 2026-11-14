# The installer step library (ROADMAP row 8): API design

**Status: design for review. No code.** Row 8's code starts after the Humboldt installer owner agrees to `docs/HUMBOLDT-CHANGE-REQUEST.md`. Everything about the Humboldt installer is quoted from its design note (`docs/INSTALLER-DESIGN.md` in the Humboldt repository, read at `origin/main` on 2026-11-14); anything that note does not say is marked **UNVERIFIED**.

What governs this: `docs/DESIGN.md` sections 2, 4.3, 8 and 9.3, and the rulings recorded in section 1 below.

## 1. Rulings this rests on

- **D4 = A** (strict reading: credentials a school holds for its own other systems never reach us; a school that wants its app-runtime secrets out of our hands installs its own copy with the installer) and **D6 = A** (recovery key shown once, a required confirmation that it was written down, and a prompt for a second holder for schools): CireSnave, board 319 (2026-10-28), verbatim "1: recommended." which the PM reads as all of D1 to D8 as recommended (PM message, 2026-11-14).
- **D3 = A and D5 = A**: board 400 (as the PM cites it; not re-read here).
- The "installer stores no credential" rule today is the Humboldt installer's (`INSTALLER-DESIGN.md` section 4). This library changes it only with the person's consent and only through the change request.

## 2. Where it lives and what it never does

A module of the `secretant` crate (working name `secretant::installer`), not a new crate: one version number per project, no new dependency, and it must build in the default feature set (44 packages, no HTTP or TLS stack; the Cloudflare placement is behind the existing `cloudflare` feature).

It **never asks, prints or logs**. The installer owns the screen: it shows the recovery key, asks for the passphrase and the "I have saved it" confirmation. The library takes values, an unlock and answers from the caller, and returns plain data. (The terminal prompt stays in the `secretant` binary, `src/prompt.rs`.)

It carries names, paths, counts and error classes only, never a value: the same canary discipline as rows 3 to 7 (section 9).

## 3. The step contract

The Humboldt installer's drivers all implement `probe` (what is there), `plan` (what would change), `apply`, `read_back` (section 2 of its note). The library offers the same four calls per step, so the installer's engine treats SecretAnt as one more driver:

| Call | Does | Writes? | Needs unlock? |
|---|---|---|---|
| `probe` | Reads the situation | no | no, unless a step says so |
| `plan` | Turns the probe and the installer's request into a list of actions; pure | no | no |
| `apply(plan)` | Does exactly the plan; **refuses a plan whose probe has changed since** (the plan carries a fingerprint of the probe: store header, names present, files present) | yes | where needed |
| `read_back` | Proves the result by reading it back: opens, counts, lists names | no | where needed |

A dry run is `probe` and `plan` and stops: the installer can show the plan file (names and non-secret values only) and ask for its typed confirmation before `apply`, the way `db-install` does.

## 4. Three steps

### 4.1 Store step (create, or use the person's existing store)

| Call | Result |
|---|---|
| `probe(path)` | `Absent`, `Present(header)` (format and which wraps, from `FileStore::inspect`, no unlock), `PendingFromAnEarlierRun`, or `Unreadable(class)` |
| `plan` | `Create { wraps }` (passphrase, OS-bound where the platform has it, recovery key always), `UseExisting`, or `Refuse(class)`. **Never `Create` when `Present`**: one store per user (DESIGN 8.1 step 3) |
| `apply` | for `Create`, see 5; for `UseExisting`, nothing is written |
| `read_back` | opens the store with each wrap the plan created, reads the version count, and reports which wraps exist; for `UseExisting`, that the person's unlock opens it |

The install **location** is an input, not a default the library hides: the installer must ask where the store goes before creating it, especially on a school server (DESIGN 8.3, the school-secrets rule). The library exposes the per-user default path (the one `secretant` already uses) so a UI can offer it.

### 4.2 Secrets step (put the product's secrets in)

Input from the installer: the list of names it needs (for Humboldt, `install::SECRETS`, which a test there already checks against the Worker's `Env`; the names are what the library receives) and, per name, a source: **given** (a value the caller holds, for example the Cloudflare token the person typed) or **generated** (the library draws random bytes of a stated length and writes them; the value is never returned). A generated value's encoding and length are the installer's to state. The Humboldt lane's answer (2026-11-14, from its `backend/src/auth/totp.rs`, not re-read here): `TOTP_ENCRYPTION_KEY` is generated, 32 random bytes written as standard padded base64 (44 characters), the one value the installer generates; typed by the person: `DATABASE_URL`, `WEBAUTHN_*`, the OAuth client ids and secrets and redirects, `RESEND_API_KEY`, `SMTP_URL`, `EMAIL_FROM`, `SECURITY_ALERT_EMAIL`, `DISTRICT_ADMIN_STAFF_IDS`. `APP_BASE_URL` and the `LINK_REQUIRES_FACTOR`, `RESET_REQUIRES_SECOND_FACTOR` and `CLIENT_IP_HEADER` flags are settings, not secrets. So the library needs a Generated source of N random bytes in standard base64 (a stated list of encodings is enough: base64 and hex); the value is never returned.

| Call | Result |
|---|---|
| `probe(unlock)` | which of the names exist and at which version (names only) |
| `plan` | per name: `Add`, `Keep` (already there; the default, so a re-run never changes a secret), or `AddVersion` (only when the installer says rotate) |
| `apply` | one in-memory merge and one atomic write for all names (as `apply_import` does), the previous generation kept as `.prev`; a failure leaves the store as it was |
| `read_back` | names present and versions; for a generated value, that it exists and is not empty, nothing more |

Consent: whether a typed credential is kept at all is the installer's decision with the person (section 4 of the change request). The library keeps nothing the installer did not hand it.

### 4.3 Place step (put the values where the program can read them)

A thin step over what exists: `deliver::plan/apply/verify` for files and env files with the ledger, and `cf::plan/apply/verify` for a Cloudflare Worker (behind the `cloudflare` feature; Worker secrets are write-only, so `read_back` says set, unset or stale, not the value). Plan, apply and verify are already dry-run first and canary-tested; the step wraps them in the contract of section 3 and adds the fingerprint.

## 5. Creating a store, and the recovery key (D6 = A)

Order, chosen so that a crash never leaves a store whose recovery key nobody saw:

1. `apply` creates the store at `PATH.pending` with the passphrase wrap, the OS-bound wrap where available, and a recovery wrap, and **returns the recovery key once**, to the caller only.
2. The installer shows it ("write this down", DESIGN 8.2 words) and takes the confirmation (section 5.1).
3. `confirm_recovery(pending, typed)` succeeds only on the confirmation; then the file is renamed to `PATH` (atomic). Only after that does the Secrets step run.
4. A `.pending` left by an earlier run holds no secret of ours yet (secrets are added after the rename), so `probe` reports it, and `plan` offers one thing: discard it and create again. A key cannot be shown a second time.

The library keeps no copy of the key, and nothing readable of it is in any file (the row 7 backup test searches plain, bare, upper, lower, hex, base64 and UTF-16 forms; the same search runs on the store and the pending file here).

### 5.1 How the person confirms the key was saved (an open choice, recommendation given)

CireSnave's words (D6 A) require "a required confirmation that it was written down". The mechanism is not stated; options:

| Option | What it proves | Cost |
|---|---|---|
| A. A checkbox ("I have saved it") | nothing a test can check; the person said so | trivial; the installer could skip it |
| **B. The person types the whole key back and the library tries to open the pending store with it** | the key was written down *and* is legible and correct | one more screen; a transcription slip is caught at install, not at the emergency |
| C. The person types two named groups (for example groups 3 and 7) | partly legible | weaker, and groups are guessable only by chance, but it is not a real unlock |

**Recommendation: B.** It is the only option the library can verify, so it is the only one a test can fail. A checkbox stays in the installer as a first screen if it wants one. **Approved by the PM on 2026-11-14 (option B)** as satisfying D6's "required confirmation it was written down"; the Humboldt lane agreed to the typed-back key.

## 6. A second holder for schools (D6 = A)

The prompt is the installer's ("a second person should be able to open this: add one?"). The library needs two things it does not have today:

- **A second passphrase wrap** (`FileStore` had `add_recovery_wrap` and `add_os_wrap`, no way to add another passphrase; added in the PR "Second passphrase wrap and wrap removal", #21). The format already allows it: `wraps` is a list, every wrap seals the same data key, `open_with` tries each in turn (`src/store.rs`, read at `origin/main`; `docs/FORMAT.md`). The new call needs its own salt and Argon2id cost and the same empty-passphrase refusal as `create`.
- **Removing a wrap**, so a holder who leaves can be taken out (DESIGN section 9 table: "an admin leaves a school"). This changes who can open the store, so it is its own reviewed call, never part of an installer step, and it refuses to remove the last way in.

Both are library work in row 8's first PR, with tests for: the second passphrase opens; the first still opens; a removed wrap no longer opens; the last wrap cannot be removed; neither passphrase is in the file.

## 7. When a store already exists

`Present`: the step never creates a second one. It needs the person's unlock to add this product's entries; if the person cannot open it, the installer says so and stops; it does not offer to create another beside it. The only writes are the names the Secrets step adds, in one atomic write that keeps `.prev`. A test shows an existing store is byte-for-byte unchanged by a plan with nothing to add. Uninstall never deletes the store (DESIGN 8.3); the library has no call that does.

## 8. Errors

Classes only, like every error in the crate: `NoStore`, `Pending`, `Exists`, `StalePlan`, `WrongUnlock`, `EmptyPassphrase`, `RecoveryNotConfirmed`, `Damaged`, `Io`, plus the existing store, delivery and Cloudflare classes carried through unchanged. No name, no value, no path in any message.

## 9. How it is tested (written before the code)

- **Canaries with negative controls**: a value, a passphrase and a recovery key go in; they appear nowhere in plans, read-backs, error text, logs (trace level too) or the store file in any of those forms; the search finds a planted string first.
- **Stale plan**: change the store between `plan` and `apply`; `apply` refuses and writes nothing.
- **Interruption**: stop after each numbered step of section 5; the result is either no store, or a `.pending` the next run discards, never a store whose key was not confirmed.
- **Confirmation**: a wrong or mistyped key leaves the pending file in place and the final path absent; a skipped confirmation cannot reach the rename (a mutation that skips it must fail a test).
- **Existing store**: unchanged bytes on a no-op plan; a second `Create` is impossible.
- **Mutations**: skip the fingerprint check; skip the empty-passphrase check; write the key to the pending file; each must fail a test.

## 10. Row 8 as pull requests

1. 8a: second passphrase wrap, wrap removal, the Store step and `confirm_recovery`, with the tests above.
2. 8b: Secrets and Place steps, plan fingerprints.
3. 8c: a worked example the Humboldt installer can follow (documentation and a test that runs it), and the plain-words text of DESIGN 8.2 as a constant the installer can show.

Each is its own PR with its own fragment; versions are the PM's.

## 11. Not in row 8

A graphical screen of our own (the installer owns the UI); remote vaults; macOS and Linux OS-bound wraps (row 9: until then an installer on those systems creates a passphrase and recovery wrap only); the web interface.

## 12. What this design could not check

- Answered by the Humboldt lane on 2026-11-14 (agreed items 1, 2, 4, 5, 7 and 8; item 4 with the typed-back key; item 6: in-process crates.io link, and its step engine, not built yet, will take library-supplied steps from the start; one Cloudflare client only, leaning to `secretant::cf`, decided at its slice 5): the `TOTP_ENCRYPTION_KEY` format (section 4.2). Licence (PM, 2026-11-14, not for CireSnave): SecretAnt stays MIT OR Apache-2.0; a proprietary app may link a permissive crate, the only duty being that the licence text and notices travel with the build. It would need CireSnave only if Humboldt code were copied into SecretAnt or SecretAnt relicensed; neither is proposed here.
- **UNVERIFIED**: that the `secretant` crate builds into the installer's single Windows executable; it uses no OpenSSL and the default build has no TLS crate (the CI job "Default build has no HTTP or TLS stack" guards that once it has run on main), but the combined build has not been tried.
