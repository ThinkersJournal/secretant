# Patent sweep

No code exists beyond an empty placeholder crate. A sweep (secret storage, key management, secret delivery) is a
precondition of the first release that contains functionality. Not legal advice; no attorney exists.

## Techniques in code (row 2, 0.0.4)

| Technique | Where | Status |
|---|---|---|
| One random data key held by several independent wraps (passphrase, recovery, OS-bound), so losing one does not lose the store | `src/store.rs` | sweep not yet run; DESIGN.md section 13 query (ii); standard envelope encryption, nothing here is cleared |
