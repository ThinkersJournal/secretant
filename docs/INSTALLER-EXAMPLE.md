# Worked example: an installer using the SecretAnt steps

For the Humboldt installer (or any installer). The code that runs this is
`tests/installer_example.rs`; it is a test, so it cannot drift from the library.
Design and contract: `docs/INSTALLER-STEPS.md`. Wording: `docs/DESIGN.md` 8.2.

The library never asks, prints or logs. **The installer asks and shows**; each
call below returns data (names, counts, classes, and the recovery key once).

## 0. Before anything: say it in plain words

Show `secretant::installer::plain_words(protection)` before first use, with
`protection` = "Windows" (or "your keychain" on a system that has one, or "a
passphrase"). The text is `PLAIN_WORDS`, the same words as DESIGN 8.2, and a
test fails if the two differ.

## 1. Store step (the person's store, with a recovery key)

1. `probe_store(path)`: `Absent`, `Present`, `Pending` (a crashed earlier run), or `Unreadable`.
2. `plan_store(path, probe, os_wrap)`: shows what will happen (create / discard the pending file and create / use the existing one / refuse). Show it; ask the person to agree.
3. `apply_store(&plan, &passphrase)`: for a new store returns the pending store and the **recovery key, once**. Show the key ("write this down") and ask for it typed back. The installer keeps no copy.
4. `confirm_recovery(&pending, &typed)`: only a correct key makes the store real (renames the pending file). A wrong one leaves nothing final; ask again or `discard_pending` and start over.
5. `read_back_store(path, unlock)`: wraps and entry count. An existing store is used, never duplicated: `apply_store` returns `Unchanged`.

## 2. Secrets step (what the product needs)

1. `probe_secrets(&store)`, then `plan_secrets(&probe, requests)`: each request is a typed-in value (`Source::Given`, such as the Cloudflare token) or a generated one (`Source::Generated`, such as `TOTP_ENCRYPTION_KEY`). A name already in the store is kept unless `rotate` is set.
2. `apply_secrets(&mut store, plan)`: one write; a re-run writes nothing.
3. `read_back_secrets(&store, names)`: name, version, non-empty. Never a value.

## 3. Place step (put the values where the program reads them)

`plan_place(&store, &ledger, placements)`, then `apply_place(&store, &mut ledger, &plan)`, then `read_back_place`: every state should be `InSync`. A plan is refused (`StalePlan`) if a target changed since it was made. For a Cloudflare Worker (feature `cloudflare`) use `place_step::cloudflare` with the same four calls.

## What the installer must not do

Log or display a value, a passphrase or a recovery key anywhere but the one screen that shows the key; keep the key; create a second store when one exists; delete the store on uninstall.
