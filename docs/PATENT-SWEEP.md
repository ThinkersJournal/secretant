# Patent sweep

Version line covered: the 0.1.0 candidate (`origin/main` 9404e56 plus open PRs #11 to #14: Cloudflare delivery, `SecretReader::list`, the no-echo prompt).
Date: 2026-11-12. Run by: the SecretAnt lane, Claude Sonnet 5.5. Method: AI-assisted web search, then a claim-by-claim read of the closest hits with
`tools/patent-claims.py` (Google Patents' public pages). **Not legal advice; not a freedom-to-operate opinion; no attorney has reviewed it.** Nothing here
clears the project. Read "Limitations" before relying on any line.

## Ideas swept

What the code does that might be new or unusual (mechanisms, not features), in claim-like sentences:

1. A store whose payload is encrypted under one random data key, where that key is separately wrapped by several independent unlockers (a passphrase through
   Argon2id, a random recovery key, an operating-system user-bound wrap), any one of which opens the store, and where losing one leaves the others working
   (`src/store.rs`). Each wrap is one AEAD encryption of the same data key; the wraps do not depend on each other.
2. A recovery key generated at the moment of adding the wrap, shown once as grouped hexadecimal text, and stored only as a wrap, never in readable form.
3. A ledger of which version of which secret was placed at which target, so a later check can tell a copy that is old (stale) from one that was edited by hand
   (drifted) without showing or comparing a value in any report (`src/deliver.rs`).
4. Writing each delivery target atomically (private temporary file, then rename) so a target that fails keeps its previous content whole and the ledger is
   updated only after the target succeeds.
5. For a host whose secrets cannot be read back (Cloudflare Worker secrets): proving the stored API token with a names-only list before any value is sent, sending
   every changed secret in one all-or-nothing request, and recording the version sent in the ledger only after the host accepts it, so `verify` can say set,
   unset or stale (`src/cloudflare.rs`).
6. A command that places stored values in a child process's environment only, removing the unlock secret from that environment, and never accepting a value as an
   argument (`src/main.rs`).
7. A read API for adapters that bounds each call with a timeout on a worker thread, keeps no cache (every read reopens the file), and reports four error classes
   that carry no store text (`src/read.rs`).

Ideas from `docs/DESIGN.md` section 13 that are **not built in 0.1.0 and not swept**: (iii) installer-time provisioning of a per-user store, (iv) configuration
references that resolve secrets without values in configuration (queried below, but not our mechanism to claim), (v) the local web management interface. They need
their own sweep when built.

## Queries (source, query, date)

All run 2026-11-12 through a general web-search tool (`WebSearch`, standard mode), **not** through the patent databases' own full-text search. The query text is
the `docs/DESIGN.md` section 13 query reworded without quotation marks (the tool does not honour them).

| # | Query (reworded) | Result |
|---|---|---|
| 1 | patent secret management synchronize credentials to cloud function environment host delivery | one patent, US12463959B2 (read below); vendor products Keeper Universal Secrets Sync and HashiCorp Vault Secret Sync appear as commercial prior art |
| 2 | patent credential vault version rotation delivery target push secrets to multiple hosting environments | no patent documents; vendor docs and blogs only |
| 3 | patent master key wrapped recovery key plurality of key encryption keys secret store data key | US10536272B2, US10148437B2, US11502833B2 (read below); two old key-recovery documents (US6654465, US6335972), not read |
| 4 | patent installer provisioning secure store user credentials during installation operating system keystore | US2024193237A1 (first-boot configuration; the claims page could not be fetched, not read), US7646874 (not read); no patent found on idea (iii) |
| 5 | patent configuration file reference to secret resolved at load time does not contain secret value schema | no patent documents; product docs only |
| 6 | patent web interface write-only credential entry step-up authentication secrets administration | no patent documents |
| 7 | patent drift detection deployed secret copy compare without revealing secret value fingerprint | no patent documents; blogs only |
| 8 | patent local credential store operating system keychain DPAPI encrypted file cross-platform secret retrieval application | no patent documents; open-source code and articles |
| 9 | patent secret rotation staged old version new version overlap window deployment credentials | no patent documents; vendor docs (AWS, Oracle, Railway) |
| 10 | patent split recovery key threshold secret sharing personal credential store backup | US11057210B1 (read below), US10516527 (claims page not fetched, not read), US11115196 (not read) |
| 11 | assignee search: HashiCorp, Infisical, Doppler, 1Password patents | no patent information returned; HashiCorp is now part of IBM per one vendor blog (the one HashiCorp patent found, US12463959B2, lists IBM as current assignee) |

## Hits

Independent claims read in full with `tools/patent-claims.py` on 2026-11-12. Status is Google Patents' own and is not the official record.

| # | Patent | Title | Assignee | Status | Claim(s) read | Overlap | Our difference | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | US10536272B2 | Encryption system with double key wrapping | Oracle | active | independent 1, 6, 11 | Wrapping a secret key with authenticated encryption | Every independent claim requires a first AEAD pass over the secret key using keys generated from a random seed, then a second AEAD pass encrypting the seed using keys generated from the encrypted secret key, and a wrapped key combining both. We encrypt the data key once per wrap under a key derived from the passphrase, a random recovery key or the OS user, with no seed and no second pass | clear on the independent claims (the seed-and-second-pass element is absent); idea 1 |
| 2 | US11502833B2 | Secure data handling and storage | MX Technologies | active | independent 1, 13, 20 | A master key and several keys | The claims require a master key generated from a combination of keys held by a plurality of key holders, re-encrypting decrypted data under a second key, and locking the engine when its configuration changes. In our store any single wrap opens the data key; nothing is combined, nothing is re-encrypted on a request, nothing locks on a configuration change | clear; idea 1 |
| 3 | US11057210B1 | Distribution and recovery of a user secret | Apple | active | independent 1, 9, 14, 17, 19 | A recovery key for user data | The claims require splitting a secret into a primary segment (stored on a server) and a shared segment divided into M threshold shares held by shareholder devices. We have no threshold sharing, no server, and a single random recovery key | clear; ideas 1 and 2. **If threshold or split recovery is ever added, this patent needs a fresh read** |
| 4 | US10148437B2 | Encryption system with key recovery | Oracle | active | independent 1, 11, 18 | Recovering a key for encrypted data | The claims recover a site key by bin recovery, filter matching and index matching on a header of the encrypted item. We recover nothing from an item; the recovery key is a stored-nowhere-readable wrap | clear; idea 2 |
| 5 | US12463959B2 | Cloud-based secrets management credential store | HashiCorp (now IBM) | active | independent 1, 7, 13 | Delivering credentials from a secrets manager to a client for cloud services | The claims require an identity-based access management system with an API, a credential store, a lease generated by a secrets management system, a scheduler that renews the lease while a session is active, and a call to revoke on session end. We have no lease, no session, no renewal, no service: the data is written once to a target and recorded | clear; ideas 3 to 5 |

## Needs review (to the PM)

No hit is `needs-review` on the independent claims read. Two items for the PM's attention instead:
- **The delivery area (ideas 3 to 5) is the likeliest place for a real overlap and is the least searched.** Commercial products do something close (Keeper's Universal Secrets Sync, HashiCorp Vault Secret Sync, per vendor pages found in query 1), and patents on them may exist that this search did not reach. Recommend a person (or a lane with a patent-database login) run Google Patents directly for assignees Keeper Security and HashiCorp/IBM with CPC classes H04L 9/08 and G06F 21/62, and read any independent claim about pushing secrets from one store to several destinations.
- The PM reviews the independent claims named above, as the PM stated.

## Limitations

- **Search coverage is thin and was not run on the patent databases.** The queries went through a general web-search tool. Google Patents' own search is JavaScript-rendered and was not queried; USPTO full text, Espacenet and WIPO were not queried directly. Most results were blogs and vendor documentation, so "no patent found" is weak evidence, not an absence proof.
- Only five patents had their claims read. US6654465, US6335972, US7646874, US11115196 were seen as titles or abstracts and not read; the claims pages of US2024193237A1 and US10516527 could not be fetched. Claims in continuations and family members were not checked; other jurisdictions were not searched.
- No CPC-class browse; no search by inventor; no search for non-patent prior art beyond what the search tool returned.
- Assignee searches for Infisical, Doppler and 1Password returned nothing usable; absence here says nothing about their filings.
- Our descriptions of what the code does are the lane's reading of its own code; the differences above were checked against `src/store.rs` (one AEAD wrap per unlocker) and the delivery code, not against a design intent.
- Idea 6 (`run` with a child environment only) and idea 7 (bounded read API) were not given dedicated queries: they are standard practice (the PM's own `with-secret` does idea 6); not expected to be novel, not cleared.
- Verdicts are the lane's, as an AI reading claims; they are not legal opinions. A lawyer's freedom-to-operate review is a separate, later purchase.
