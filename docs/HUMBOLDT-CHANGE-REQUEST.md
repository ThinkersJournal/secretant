# Change request to the Humboldt installer design: SecretAnt as a step

**From** the SecretAnt lane. **To** the Humboldt lane (owner of `docs/INSTALLER-DESIGN.md` and the installer slices). **Asked by** the PM.
**What is asked:** agree, amend or decline each numbered change below. Nothing here is built; SecretAnt's row 8 code starts after your answer. Our side of the design is `docs/INSTALLER-STEPS.md` in the SecretAnt repository.

Sources read: your `docs/INSTALLER-DESIGN.md` at `origin/main` (2026-11-14), sections 1, 2, 4, 7.3, 8 and 10; SecretAnt `docs/DESIGN.md` sections 2, 8 and 9. CireSnave's rulings (board 319, "1: recommended.", as relayed by the PM): D4 = A, D6 = A.

## Why

Requirement 1 is that every install of our software sets up SecretAnt for the installer's user. Your note says the installer "stores no credential" (section 4); SecretAnt's design (section 8.1) changes that only with the person's agreement. D4 = A is the reason the Humboldt installer exists at all: a school that wants its app-runtime secrets out of our hands installs its own copy. D6 = A says what that install must require so a lost key does not mean lost secrets.

## The changes

**1. Section 4, "stores no credential".** Keep it as the default. Add: with the person's explicit agreement, a credential they typed (the Cloudflare token) may be kept in *their own* SecretAnt store so `reconfigure` need not ask again; without agreement nothing changes. The consent text is yours; SecretAnt supplies only the words about where the secret is kept. SecretAnt keeps nothing the installer did not hand it.

**2. Section 2, drivers: add a "store" step before the hosting driver and a "place" step after it.** Same four calls (`probe`, `plan`, `apply`, `read_back`). The library offers the Store step (create the person's store or use the one they have), the Secrets step (put the product's secrets in) and the Place step (files, env files, a Cloudflare Worker). Your wizard never branches on the target outside its driver; the SecretAnt steps are not target-specific.

**3. `install::SECRETS`.** The list stays yours and its test stays. Its names become the names the Secrets step is asked to put in. Please tell us, for each: whether the value is typed by the person or generated, and for a generated one its length and encoding. We could not find the format `TOTP_ENCRYPTION_KEY` needs in your note (**UNVERIFIED** from our side).

**4. The first screens of a new install** (all D6 = A):
- before first use, the plain words in SecretAnt `docs/DESIGN.md` 8.2 (we will offer them as a constant to show);
- the recovery key shown once with "write this down", then a **required confirmation**. Our recommendation is that the person types the key back and the library tries it (`docs/INSTALLER-STEPS.md` 5.1, option B); a checkbox alone proves nothing a test can check. The final store file does not exist until that succeeds;
- for a school (a school server or an admin machine, not a single person's laptop), a prompt for a second holder.

**5. Where the store lives.** The installer asks before creating it. On the Docker server target the store belongs to the account that runs the installer, on that server or an admin machine, never on a host we operate (the school-secrets rule). If a store already exists for that user, it is used and a second one is never created; only this product's names are added.

**6. Section 7.3, reuse as a library.** The same in-process rule you set for the db tools: the installer links the `secretant` crate (from crates.io, MIT OR Apache-2.0) and calls the steps in-process. Please confirm your step engine can take a library-supplied step (**UNVERIFIED** from our side). Dependency facts, measured at SecretAnt `origin/main` 2026-11-14: the default build has no HTTP or TLS crate (44 packages in its normal tree), no OpenSSL, and `cloudflare` is an optional cargo feature. We would like to know whether your Cloudflare driver will use SecretAnt's Worker secret placement (`secretant::cf`, behind that feature, which brings a TLS stack) or keep your own; either is fine, but there should be one client in the installer, not two.

**7. Uninstall.** Never deletes the person's store. The library has no call that does.

**8. Slices (section 10).** SecretAnt's steps plug in at your slice 3 (the step engine). We suggest a slice "3b" for the Store and Secrets steps and "5b" for the Place step beside the Cloudflare driver (slice 5). We start only after you answer.

## What we need back

- Agree, amend or decline for each of 1 to 8.
- The answers to the questions in 3 and 6.
- Whether the licence position (your section 1: "All rights reserved") affects linking an MIT OR Apache-2.0 crate. We make no legal claim; it is for CireSnave and a lawyer, and we flag it only so it is not found late.

## What SecretAnt promises in return

No prompt, print or log from the library; names, counts and error classes only; one store per user; a plan that is refused if the situation changed; nothing deleted; the recovery key never stored anywhere readable.

— lane: secretant
