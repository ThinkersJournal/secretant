# Roadmap

Status 2026-11-16: rows 1 to 8 are merged (row 7 is #17 and #19, row 8 is #20 to #26) and 0.1.0 is set but unpublished; rows 9 to 11 are blocked (see below). Design is `docs/DESIGN.md` (merged, #1). Row numbers here are build order; DESIGN.md section 12 slice numbers are in
brackets. One PR per row (or slice of a row); known-bad tests first; the PM allocates the version at the gate.

**Who is waiting:** ConfigurAnt rows 4 and 25 (an adapter crate that implements `SecretSource` for SecretAnt; held until SecretAnt is on
crates.io with a stable read API); the Humboldt installer (`docs/INSTALLER-DESIGN.md`: keep a school's secrets in one place the school controls).

## v1 = rows 1 to 6 (all merged)

Smallest set that lets ConfigurAnt publish its adapter (rows 1-3) and lets the Humboldt installer keep and place a school's secrets (rows 4-6).

| Row | Deliverable | Test (known-bad first) | Unblocks | Waiting |
|---|---|---|---|---|
| 1 [1] | Library core: `SecretValue` (no Debug/Display/Clone/Serialize, wiped on drop), `Store` trait, the local encrypted file format (random data key, authenticated cipher, the key wrapped by a passphrase wrap; wrap list designed for more), atomic write with one previous generation, `put/get/list/describe` with versions and non-secret metadata, private Redact stub | canary value never in Debug, errors, logs or the file; one flipped byte fails to open loudly; wrong passphrase is a named error; mutation that leaks must fail | everything below; ConfigurAnt can code against the API | nobody can start before it |
| 2 [2] | Key wraps: recovery key (shown once) and Windows OS-bound wrap (DPAPI) so an unattended program opens the store as the same user; explicit owner-only ACL on Windows; several wraps open one data key | losing one wrap still opens via another; no wrap opens it = named error; store file ACL asserted | unattended `get` (ConfigurAnt fetch at program start) | ConfigurAnt adapter |
| 3 [3] | Publish-ready read API for adapters: `open(config)` plus `get(name)` with error classes `NotFound/Denied/Unreachable/TimedOut`; bounded by timeout; no disk cache; README first screen states the same-user limit. Crates.io release 0.1.0 (PM publishes) | adapter-shaped test against ConfigurAnt's `SecretSource` error classes; errors carry no store text | **ConfigurAnt rows 4 and 25** (they write `configurant-secretant`, D8 A) | ConfigurAnt |
| 4 [1] | CLI `secretant`: `init`, `put`, `get`, `list`, `rotate`, `run NAME -- cmd` (value in the child's environment only) | `run` puts the canary in the child env only, never argv; `list` never prints values | person-facing use; installer can shell out | Humboldt installer |
| 5 [4] | Delivery plan/apply/verify for file (owner-only perms) and environment, drift report that never shows values; records what was placed where | pushed file permissions checked; drift detected after a hand edit; failed target stays stale, never half-rotated | ConfigurAnt `env`/`file:` sources work with no new code | Humboldt Docker target |
| 6 [5] | Cloudflare Worker secret delivery (first check the API; Worker secrets are write-only so `verify` says set/unset) | fake-API test: token scope and failure handling; canary absent from requests logged | the Humboldt Worker's secrets (`TOTP_ENCRYPTION_KEY`, database URL) placed from the school's store | Humboldt installer |

## After v1, in order (rows 7, 8 and 10 done; 9 and 11 partly blocked)

| Row | Deliverable | Needs |
|---|---|---|
| 7 [6] | Backup, export/import bundle (dry-run first), restore test, `doctor` | 1, 2 |
| 8 [7] | Installer step library (`probe/plan/apply/read_back`), recovery-key confirmation, Humboldt change request | 2, 7 |
| 9 [2] | macOS Keychain and Linux Secret Service / `systemd-creds` wraps | 2; 2026-11-19: probe job `.github/workflows/os-store-probe.yml` tests whether GitHub-hosted macos-latest (temporary keychain) and ubuntu-latest (gnome-keyring under dbus-run-session) can run the wraps' tests; RESULT 2026-11-19 (PR 40, run 44594742660): both jobs PASSED on GitHub-hosted runners (a keychain write and read back in 3 s; a Secret Service write and read back in 16 s), so row 9 needs no self-hosted runner; the wraps' tests run on those two jobs' setup |
| 10 [3] | SecretAnt's own ConfigurAnt schema and the cycle check | 3; 2026-11-19: ConfigurAnt 0.7.2 is on crates.io; `configurant.toml` and `tests/own_schema.rs` done (settings that exist today; the rest of DESIGN 6.1 as each is built) |
| 11 [8] | Adopt RedactAnt and AuditAnt when published | those; 2026-11-19: RedactAnt 0.1.2 is published and already used by `SecretValue`; AuditAnt is only a 0.0.0 placeholder on crates.io, so that half is blocked on its lane |

## NOT in v1

- Web interface (needs HTTPAnt, APIAnt, WebHostAnt, none built); D7 A puts it last.
- Pull mode / local agent, consumer policy.
- Remote vault clients (OpenBao, Infisical, 1Password, cloud managers).
- Hardware-bound wraps (Hello/FIDO2/TPM), Shamir-split recovery keys.
- Roles beyond the owner; SentinelAnt/NotificAnt alerts; hash-chained audit beyond a private stub.
- macOS and Linux OS-bound wraps (row 9): v1 targets Windows first because the installer does; passphrase and recovery wraps work everywhere.
- `with-secret` convergence (D8); provider-side rotation; Cloudflare targets beyond Worker secrets.

## Open decisions (the PM sends them to CireSnave)

Full text and options: `docs/DESIGN.md` section 14. Rulings (the PM, 2026-11-14): board 319 (2026-10-28), CireSnave verbatim "1: recommended.", ruled all of D1 to D8 as recommended, so **D4 = A and D6 = A** (row 8's installer requirements: school secrets stay with the school; recovery key shown once, a required confirmation it was written down, a prompt for a second holder). D3 = A and D5 = A: board 400. No decision blocks rows 1 to 8 now; row 8's remaining blocker is the Humboldt installer owner's agreement to `docs/HUMBOLDT-CHANGE-REQUEST.md`. D2 and D7 gate the web interface only; D8 gates row 10 and `with-secret` work.
