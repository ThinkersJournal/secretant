# Patent sweep

Version 0.0.4: no sweep has been run; nothing in 0.0.x is released with functionality.

Not legal advice; no attorney exists. A sweep (secret storage, key management, secret delivery) is a precondition of the first release that contains
functionality. Nothing here is cleared. The full query list is in `docs/DESIGN.md` section 13.

## Ideas

| Technique | Where | Status |
|---|---|---|
| One random data key held by several independent wraps (passphrase, recovery, OS-bound), so losing one does not lose the store | `src/store.rs` | not yet swept; DESIGN.md section 13 idea (ii); standard envelope encryption |
| One personal store with versions and metadata driving delivery to host-native stores: a ledger of which version was placed where, so a later check tells an old copy (stale) from a hand edit (drift) without showing a value; each target written atomically so a failed one stays on the old value | `src/deliver.rs` (file and environment-file targets); host-native stores not built | not yet swept; idea (i) |
| Write-only host secret delivery verified without reading the value back: a preflight list proves the token before any value is sent, one all-or-nothing request, and a ledger of the version last sent tells set from stale | `src/cloudflare.rs` | not yet swept; idea (i) |

## Queries

None run yet. To run: the DESIGN.md section 13 queries on Google Patents, USPTO, Espacenet and WIPO, recording date and source for each.

## Hits

None recorded (no queries run).
