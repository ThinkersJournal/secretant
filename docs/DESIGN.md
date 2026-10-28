# SecretAnt: design note

Status: draft 1, 2026-10-28. Docs only; no code exists. Written by a lane (Sonnet 5.5) for CireSnave and the PM. Not legal advice. Every fact I did not read in a file or run myself is marked **UNVERIFIED**. Facts I read are cited by file; other repos were read at `origin/main` (or the named branch), not from working trees.

## 1. Goal and non-goals

CireSnave's requirement 1, verbatim (2026-10-28):

> "Any install of any of our software would need to include setting up SecretAnt for the person doing the install so they, too, can keep their secrets in one central place they control. That was my underlying point. All software I install would benefit from having all of my secrets installed in one place. All software John Doe installs would benefit from having all of John Doe's secrets installed in one place."

**Goal.** One place, controlled by the person (or school) that owns them, where all their secrets live; one interface that our software uses to ask for a secret by name; and a way to get a secret to where a program runs (deliver it to a host's own store, or let the program fetch it), chosen by configuration.

**Non-goals (v1).**
- Not a hosted service. We run no SecretAnt server that holds anyone's secrets (section 2).
- Not an enterprise secrets platform (dynamic database credentials, PKI, leasing for thousands of clients). OpenBao-class tools do that (section 10); we may talk to them, we do not rebuild them.
- Not a password manager for people's websites (browser autofill, sharing logins).
- Not isolation from a hostile process of the same user. Every tool in this portfolio states that limit (`with-secret`, ConfigurAnt's `docs/SECRET-SOURCES.md` section 3); SecretAnt states it too and does not pretend otherwise.
- Not a replacement for `with-secret` on day one (section 3.4).
- Not a new cryptographic primitive or protocol. We assemble reviewed ones (section 4.2).

## 2. Who holds what

| Holder | Holds | Where | Never holds |
|---|---|---|---|
| **A person** (John Doe, CireSnave) | their own secrets: API tokens, database URLs, signing keys, passwords for services they run | their own machine(s), in their SecretAnt store | anyone else's |
| **A school** (or district) | the school's secrets: hosting tokens, database URLs, mail credentials, the keys of its own deployment | on a machine the school controls (an admin's computer or the school's server) | secrets of other schools |
| **Us** (Thinker's Journal / Evans Labs) | our own operating secrets (our Cloudflare token, our signing keys, our CI credentials) | our own SecretAnt stores | **any school's secret, and any person's** |

CireSnave's requirement 2, verbatim: "A school's secrets stay with the school; never stored in a service we run."

How the rule is kept, in plain steps:
1. SecretAnt is a program and a file format that run on the owner's machine. There is no SecretAnt cloud, no account with us, no telemetry, no key escrow, no "forgot my master key, ask us" path. That is the only way "never stored in a service we run" can be checked by reading code instead of trusting a promise.
2. A test in the repo asserts that the code has no outbound network call except to targets the owner configured (a delivery target or a remote vault the owner named). A deny-by-default egress list is part of the design.
3. Backups and sync go to places the owner picks (a USB drive, their own cloud bucket). The backup is ciphertext and the key is not in it (section 9.4).

**Where the rule is harder than it sounds (decision D4).** When a school uses a service we run (today the Humboldt Worker on our Cloudflare account, per `docs/INSTALLER-DESIGN.md` on `origin/docs/installer-design`, section 1), the secrets that service needs in order to run (its database URL, `TOTP_ENCRYPTION_KEY`) sit in a host we operate. That is a contradiction with the rule's strict reading. The clean reading I propose: *credentials a school holds for its own other systems (its Cloudflare account, its mail account, its database) never reach us, and a school that wants its app-runtime secrets out of our hands self-hosts, which is what the Humboldt installer exists to allow.* CireSnave must confirm this reading (section 14, D4).

## 3. The interface apps use

### 3.1 What an app can do

An app or tool, through the `secretant` library (or the CLI, section 3.3), can:

| Call | Meaning | Returns |
|---|---|---|
| `get(name)` | the current value | an opaque `SecretValue` (no `Debug` text, no `Display`, no `Clone`, no `Serialize`, wiped on drop), same discipline as ConfigurAnt's `SecretValue` |
| `get_version(name, n)` | an older version (for staged rotation) | same |
| `put(name, value, meta)` / `rotate(name, new_value)` | create; add a new version (old versions kept until retired) | version number |
| `list()` / `describe(name)` | metadata only | names, versions, kind, created, `rotate_by`, last used, delivery targets, who may read it |
| `deliver(plan)` | place secrets into a host-native store (section 5) | a per-target result: placed / unchanged / failed, never the value |
| `verify(plan)` | read back what can be read back (names, set/not-set, or a fingerprint) | drift report |
| `export` / `import` | section 9.5 | an encrypted bundle |

A value only ever leaves the library through `get`. `list`, `describe`, `verify`, errors, logs and audit events never contain a value (see 3.5).

### 3.2 Names, versions, metadata

- **Name** is the identity and is not secret (it may appear in `describe`, `explain`, logs). Follow the portfolio's vault-name convention so existing habits carry over: `<SERVICE>_<PROJECT>_<PURPOSE>`, shared ones `<SERVICE>_<PURPOSE>`, read-only variant `_RO` (`CIRESNAVE-EXPECTATIONS.md` 6.12, marked there "proposed by the PM, to confirm"). For people outside the portfolio, a namespace field (`acme-site/DATABASE_URL`) replaces the prefix convention; both map to one string form. **Check:** 6.12 is a convention proposal, not a ruling; the format is a decision-light choice for the first slice.
- **Version**: every `put` or `rotate` appends a version; old versions are kept until the owner retires them, so a staged rotation (new and old both valid for a window) can be expressed.
- **Metadata** (all non-secret): kind (token, password, key, url-with-credentials), `rotate_by` date (the vault has this today, section 3.4), created/changed times, allowed consumers, delivery targets (ids, not values), free-text note.
- **Env variable name is not the identity.** The vault today separates the NAME from the env VAR the tool reads (`vault set NAME --env VAR`, from `with-secret`'s own help text). SecretAnt keeps that split: a *binding* maps a name to the variable or file a given program expects.

### 3.3 Three ways to ask, in order of preference

1. **Library call** in-process (`secretant::open(config)?.get(name)`). Needs no daemon.
2. **Deliver ahead of time** (section 5): the program never asks; its host's store already holds the value, and the program reads it the way it already reads configuration (environment or a file). ConfigurAnt already supports both (`env` first; `source = "file:<name>"`, built in 0.2.34, per `docs/SECRET-SOURCES.md`).
3. **Wrapper**: `secretant run NAME[,NAME] -- command args` puts the value in the child's environment only, like `with-secret NAME -- command`. Useful for tools we do not control.

No always-on background service is required by v1. A local agent (a socket on the machine) is only for the optional pull mode (section 5.3).

### 3.4 What `with-secret` does today versus what SecretAnt would do

`with-secret` facts below come from its own `--help` text (run on this machine; the command lists usage only, I did not run any subcommand that reads a vault) and from agentlife `docs/DESIGN-REVISION-1.md` and `-2.md`, read at `origin/main`. **I did not read `WITH-SECRET-DESIGN.md` or the source** (it moved out of OverMind; per OverMind's `ARCHITECTURE-LAYERS-SPEC.md` it is destined for a `consent` repo). Anything beyond that is **UNVERIFIED**.

| | `with-secret` today | SecretAnt (proposed) |
|---|---|---|
| Purpose | stops *accidental* exposure of secrets to AI agent lanes; a per-use approval gate | a person's/school's general secret store and delivery tool |
| Approval | each use needs approval via Windows Hello (help text); one approval is one lane, one secret, void on lane restart, until a chosen end (help text) | none per use for the owner's own programs; optional approval step through the same `user-request` consent mechanism for sensitive names |
| Who asks | named "lanes" (agent sessions), with an allow-list (`vault allow NAME --lanes ...`) | "consumers" (a program identity, an OS user); no lane concept |
| Entries | `NAME`, `--env VAR`, `--access read|write`, `--rotate-by DATE` (help text) | same ideas plus versions, kinds, delivery targets, namespaces |
| Delivery | into one child process's environment only (help text) | env, file with permissions, Docker secret, Cloudflare Worker secret, others as adapters |
| Log | an access log with command and reason (help text) | audit trail through AuditAnt (section 7.5) |
| Platforms | Windows Hello is Windows-only; other OS behaviour **UNVERIFIED** | Windows, macOS, Linux from the start (via an OS layer, section 11) |
| Stated limit | does not stop a process holding a secret from printing it, nor a same-user process from decrypting the vault (help text) | same limit, same wording |
| How the vault file is encrypted | **UNVERIFIED** (agentlife `DESIGN-REVISION-2.md` says its approval cache is HMAC-signed with a DPAPI-protected key "exactly the `with-secret` `ApprovalCache` pattern", so DPAPI is used at least there) | section 4.2 |

**Relationship (open).** `with-secret` stays as the agent-fleet gate. The cleanest end state is that its vault becomes one more *store* behind SecretAnt's interface, with the Hello approval as a policy layer on top. That migration is not part of this design; it needs the `with-secret` authors' design read first (D8 below, and the PM's standing note that the vault must not stay in OverMind indefinitely).

### 3.5 No value in logs: RedactAnt

RedactAnt is "redaction types, safe Display/Debug, fingerprints" (`PORTFOLIO-ROADMAP.md`, name queued, **not built**). SecretAnt needs three things from it: (a) a secret-carrying type whose formatting is blank; (b) a *fingerprint* (a keyed hash prefix) so two logs can say "same secret" without the value; (c) a scrubber for errors from adapters. Until RedactAnt exists SecretAnt carries a small private copy, behind a trait, and drops it when RedactAnt publishes (this is the "stub" in section 11). Every rule has a canary test with a negative control (a mutation that leaks must fail the test), copying the pattern of S1-S10 in ConfigurAnt's `docs/SECRET-SOURCES.md` section 3.

## 4. Stores and adapters

### 4.1 Layers

```
 app / installer / web UI / CLI
            |  (3.1 interface)
      SecretAnt core: names, versions, metadata, policy, audit hooks
            |
   +--------+----------------------+----------------------+
   | STORE (where values rest)     | KEY WRAP (what opens it) | DELIVERY TARGET (where values go)
   | local encrypted store (default)| OS keychain / DPAPI     | file with permissions
   | remote vault client (optional) | passphrase (Argon2id)   | Docker/Compose secret
   |                               | recovery key            | Cloudflare Worker secret
   +-------------------------------+-------------------------+ other hosts (adapters)
```

Each of store, key wrap and delivery target is an *adapter chosen by id*, using the portfolio's declare-needs / list-providers / pick / re-check pattern (`PORTFOLIO-ROADMAP.md`, ant-family section; CapAnt is "the capability engine"). A need nothing satisfies is an error naming what is unmet; nothing falls back silently.

### 4.2 The local encrypted store (default and only store in v1)

- One file (or one blob) holding all entries, encrypted with an authenticated cipher under a random *data key*; the data key is itself wrapped (encrypted) by one or more *key wraps*. Several wraps can open the same data key, so losing one (say, the laptop's keychain) does not lose the store if another (passphrase, recovery key) survives.
- Primitives: use reviewed libraries, not our own: the `age` format (the `rage` Rust crate) or a libsodium-style XChaCha20-Poly1305 with Argon2id for passphrases. **UNVERIFIED**: I have not read either crate's current docs, audit status or MSRV; choosing between them is the first design task of the code slices (section 12, slice 1).
- Atomic writes: write a new file, flush, rename; keep one previous generation. PersistAnt's blob kind promises atomic replace on the `fs` backend (README at `origin/main`), and CireSnave ruled on 2026-10-21 that projects declare storage needs and pick through PersistAnt (as recorded in the PM's memory notes; **I did not re-read the ruling's text**). Because the blob is ciphertext, any PersistAnt backend (local disk, the owner's own bucket) is safe to hold it; the *key wrap* never goes through PersistAnt. PersistAnt is therefore an optional dependency used for the blob; a plain-file fallback exists so SecretAnt can be the first thing installed on a bare machine.
- Entry values are zeroized on drop (ConfigurAnt accepted `zeroize` for the same reason, decision 3 in `docs/SECRET-SOURCES.md`). Memory is not locked (`mlock`); that limit is stated.
- File permissions: owner only; Windows ACL set explicitly (`std` has no ACL API, which ConfigurAnt's `file` source already hit: "Windows has no permission check", `docs/SECRET-SOURCES.md` 4a). That needs the OS layer (section 11).

### 4.3 Key wraps (what unlocks the store)

| Wrap | What it is | Good for | Cost/limit |
|---|---|---|---|
| OS-bound (Windows DPAPI / Credential Manager, macOS Keychain, Linux Secret Service or `systemd-creds`) | the OS releases the key to this user on this machine | no password to type; unattended jobs by the same user | tied to the machine and the user profile; any same-user process can ask (stated limit); a profile reset loses it. **UNVERIFIED**: exact API behaviour per OS, and whether `systemd-creds` is present on a given distro |
| Passphrase | key derived with Argon2id from something the person types | portable between machines; survives OS reinstall | a person must type it; weak passphrase = weak store |
| Recovery key | 256-bit random key shown once, written on paper | the only way back when both above are lost | whoever holds the paper holds the store; must be stored apart from the laptop |
| Hardware (Windows Hello/WebAuthn/FIDO2 hmac-secret, TPM) | key released after user presence | strongest local gate | **UNVERIFIED** availability and Rust support per OS; later slice |

A new install creates the store, wraps with the OS-bound key *and* a recovery key (printed/shown once with a "write this down" step), and offers a passphrase. The installer cannot silently skip the recovery key (section 9.3).

### 4.4 Host-native stores as delivery targets (not as the source of truth)

A Cloudflare Worker secret, a Docker secret, or a file under `/run/secrets` is *where a secret is placed so a program there can read it*. They are derived copies. The store stays the one source of truth (requirement 1). SecretAnt records *which* names it placed *where* and when, so rotation and removal reach every copy and `verify` can report drift. Consequence worth saying plainly: "one central place" means one place you *manage* them, not the only place a secret physically exists; a deployed app necessarily has its own copy. **Check:** the PM's analysis does not state this; it matters for the threat model (a host compromise reveals the copies on that host only).

### 4.5 Optional remote vault client

An adapter that reads from or writes to an existing vault the owner already runs (OpenBao/Vault-compatible, Infisical, a cloud secret manager). Off by default, configured by ConfigurAnt, never required. Reasons to include it: a school's district may already run one; CireSnave's wording "whether SecretAnt reads from a central vault or deploys secrets should be configurable" (section 6) requires a way to read from one. Each remote adapter is its own crate and slice (section 12, slice 11). **UNVERIFIED** which remote products are worth the first adapter; D3 asks.

## 5. Push, pull, or configurable

### 5.1 The two modes defined

- **Push at deploy time.** When the owner deploys or rotates, SecretAnt reads from its store and writes secrets into the host's own mechanism. The running program never talks to SecretAnt.
- **Pull at run time.** The running program (or its launcher) asks a SecretAnt/vault each time it starts (or on a refresh) and keeps the value in memory.

### 5.2 Checking the PM's analysis

The PM's points hold, with changes:

| Claim | Check |
|---|---|
| Pull has a first-secret (bootstrap) problem | **True.** To ask the vault the program needs a credential for the vault. That credential is the "first secret"; it must be delivered by something that is *not* the vault (a push, an OS-bound key, a hardware token). So pull cannot remove a push, it only moves what is pushed. The honest summary: *every design has one secret delivered out of band; push makes it a deploy-time credential held by the owner, pull makes it a runtime credential held by the app.* |
| A vault on a laptop is unreachable from Cloudflare | **True and decisive** for our own current case: the Humboldt Worker/Container on Cloudflare cannot call a laptop. Pull there would need a vault with a public, always-on address, which is a service somebody runs (violates the spirit of requirement 2 unless the school runs it). |
| Pull costs availability and widens blast radius | **True.** If the vault is down at start, the app cannot start (a cache fixes that and reintroduces a second copy). A compromised app holding a vault credential may read *every secret it is allowed*, not only its own, unless scoped. |
| Push avoids most of these | **Mostly.** It has its own costs the analysis omits: (a) **rotation requires an action**: a pushed secret changes only when someone pushes; pull picks up a new value at next fetch with no deploy. (b) **drift**: the host's copy and the store can diverge if someone edits the host by hand. (c) **the push credential** (a Cloudflare API token that can write secrets) is itself a high-value secret in the store, used only at deploy time. (d) many hosts do not let you read a secret back, so `verify` can confirm "is set" but maybe not "equals" (**UNVERIFIED** per host; Cloudflare Worker secrets are, as I recall, write-only after set). |
| Recommended: push default, pull optional, both by ConfigurAnt | **Agree.** I add one thing: because ConfigurAnt already puts `env` first and has a built-in `file:` source, push to environment or a secrets file needs *no new code in the app or in ConfigurAnt*, which is the strongest argument for push-as-default. |

### 5.3 Pull as an optional mode

Pull is useful where the program and the store are on the same machine (a developer's laptop running a local service) or on a network the owner controls. Design for it:
- The program asks through a local agent (a Unix socket or Windows named pipe, owner-only). No network listener by default.
- The agent authenticates the caller by OS identity (same user; stated limit applies) and by the *consumer id* in the store's policy (which names that program may read). A program can never list names it was not granted.
- Calls have a timeout and a clear error class (`NotFound`, `Denied`, `Unreachable`, `TimedOut`), matching ConfigurAnt's `SourceError` classes so an adapter is a thin wrapper (section 6.3).
- No on-disk cache by default; an opt-in in-memory cache with a TTL. Never a plaintext disk cache.

### 5.4 Rotation

- **Push:** `rotate NAME` writes a new version; `deliver` places it; the program picks it up at its next restart (or live if it re-reads its file). A rotation plan lists every target that holds the old version and reports each one's outcome; a target that failed keeps the old value and is listed as stale (nothing is silently half-rotated).
- **Pull:** the new version is served at the next ask. A "staged" rotation serves both versions during a window.
- `rotate_by` dates generate reminders through SentinelAnt/NotificAnt (section 7.6), not a nag loop in SecretAnt.
- Rotating a *third party's* credential (making Cloudflare issue a new token) is out of scope in v1: SecretAnt stores and places the new value; the owner obtains it. Provider-side rotation adapters are a later slice.

### 5.5 "Configurable"

Both modes are selected by ConfigurAnt settings (section 6.1): a global default mode, and a per-name or per-target override. A name delivered by push and marked `pull = deny` can never be fetched by an agent call.

## 6. ConfigurAnt integration

CireSnave's requirement 3, verbatim:

> "ConfigurAnt should be used to configure SecretAnt. Similarly, whether SecretAnt reads from a central vault or deploys secrets should be configurable through ConfigurAnt. SecretAnt should have a web interface for configuration, maintenance, and secrets management. That web interface should be hosted via WebHostAnt. WebHostAnt should be configured via ConfigurAnt. Basically, no matter which piece of our software we're talking about, it should use our other tools where possible, and beneficial."

### 6.1 What is a setting (SecretAnt's own ConfigurAnt schema)

| Setting | Notes |
|---|---|
| `store.adapter`, `store.path` (or PersistAnt backend id + location) | which local store, where. A path is non-secret |
| `keywrap.methods` (ordered list: `os`, `passphrase`, `recovery`) | which wraps are enabled |
| `mode.default` = `push` / `pull` / `both`; per-name override in the entry's metadata | section 5 |
| `delivery.targets` (ids, kinds, non-secret addresses: a Cloudflare account id, a Docker host, a file directory) | the credential for a target is a secret *entry*, referenced by name |
| `remote.vault.adapter`, `remote.vault.address` | optional client (4.5); the token is an entry reference |
| `audit.sink`, `alerts.*` thresholds | sections 7.5-7.6 |
| `web.enabled` (default false), `web.bind` (default `127.0.0.1`), `web.port`, `web.allow_remote` (default false) | section 7 |
| `rotate_by` default horizons, `retire_after` for old versions | policy |
| `egress.allow` | the deny-by-default network list from section 2 |

ConfigurAnt's rules apply to this schema: unknown keys refused, types checked, every setting explained by `describe`/`explain`, a front end available (CLI/env, TUI, GUI per `CONFIGURANT-SPEC.md`).

### 6.2 What is never a setting

Secret values; the master/data key; a passphrase; the recovery key; the web UI's session-signing key and any bootstrap token; and any credential at all (delivery credentials are *entries*, referenced by name). ConfigurAnt refuses a secret in a file, a command-line argument or a default (`docs/SECRET-SOURCES.md` section 1); SecretAnt's schema marks the few secret-like items `secret = true` so that rule enforces itself. A test loads SecretAnt's schema with a canary and asserts it appears nowhere.

### 6.3 ConfigurAnt's `SecretSource` row: the SecretAnt adapter

`docs/SECRET-SOURCES.md` section 2 and slice 4 already reserve this: SecretAnt "would ship its own adapter crate that implements `SecretSource`", held until SecretAnt is on crates.io (crates.io-only dependency rule, `CLAUDE.md` section 9). The trait read there is `name()`, `interface_version()`, `fetch(reference) -> SecretValue` with error classes `NotFound`, `Denied`, `Unreachable`, `TimedOut`. Design consequences:
- Reference form: `source = "secretant:<NAME>"`, the NAME being the identity. The environment still wins over a source (decision 2 there); with push-to-env that means the pushed value and the source agree and nothing is fetched twice.
- Crate name `configurant-secretant` (or inside SecretAnt as an optional feature): **decision D8**; both work. I recommend a separate small crate so ConfigurAnt takes no dependency on SecretAnt.
- Fetch is bounded by a timeout (ConfigurAnt rule S6), makes no disk cache (S7), and returns no text from the store in an error (S3).
- **No cycle.** SecretAnt's *own* schema contains no `source = "secretant:..."` entry (it would ask itself for the key it needs to start). The schema checker rejects one. SecretAnt starts from file + env + an OS-bound key only.
- ConfigurAnt's existing rule that the `with-secret` wrapper needs no source (decision 4) stays true: SecretAnt's push path produces the same environment variable.

### 6.4 Where the tools meet circularly, and how it is cut

SecretAnt is configured by ConfigurAnt; ConfigurAnt's secrets may come from SecretAnt; the web UI is hosted by WebHostAnt, which ConfigurAnt configures, and WebHostAnt needs a TLS key (a secret) when it serves beyond loopback. Cut: *tier 0* (SecretAnt core, its config, the OS-bound key) depends on nothing from tier 1; *tier 1* (web UI, WebHostAnt) reads its secrets from tier 0 by library call at start. Nothing in tier 0 imports anything in tier 1.

## 7. The web interface

### 7.1 Scope

Configure (edit SecretAnt's own ConfigurAnt settings), maintain (list entries and their health, run `verify`, rotate, retire versions, backups, export/import, see the audit trail), and manage secrets (add, replace, delete, mark rotate-by, choose delivery targets). Same operations as the CLI, nothing the CLI cannot do (so the CLI is the test oracle).

### 7.2 Hosting: WebHostAnt, HTTPAnt, APIAnt

- **WebHostAnt** is "reserved name" only; its README says it plans quick deployment to common hosts and "local hosting with automatic TLS certificates (for example from Let's Encrypt)", designed to work with ConfigurAnt; its ROADMAP says wait for the Humboldt installer to show what the interface needs, then a design note and a build-or-adopt comparison (Caddy etc.) before any code (`origin/main` README and ROADMAP read). So the web UI is a *late* slice and also a *second consumer* that helps WebHostAnt extract its interface (the roadmap wants two consumers).
- **HTTPAnt** (core + server half, "confirmed", repo not yet moved) and **APIAnt** ("API scaffolding on HTTPAnt server: health, rate limit, versioning, auth wiring, OpenAPI", name claimed) are not built (`PORTFOLIO-ROADMAP.md`, Ant table). SecretAnt's API is thin and versioned (`/v1/...`); a stub server adapter is acceptable behind the HTTPAnt trait until HTTPAnt exists. I read no HTTPAnt or APIAnt source: **their interfaces are UNVERIFIED**.
- The UI itself: server-rendered pages, minimal JavaScript, no third-party scripts, strict Content-Security-Policy. No single-page-app dependency tree to supply-chain (section 9).

### 7.3 Sign-in and authorisation

- The person proves presence: a **passkey (WebAuthn)** or the OS prompt (Windows Hello via the `user-request` consent crate the portfolio already uses for `with-secret`). Passwords are not the primary path. AuthAnt (the rename of auth-framework, "built, lane running") has WebAuthn support, but I read only its README header, so which APIs fit is **UNVERIFIED**; the alternative is the consent crate alone for a local-only UI.
- A first launch prints a one-time URL token to the terminal that started it; it enrols the first passkey. After that the token is dead. No default account, no default password.
- **Authorisation, v1: one role, the owner.** Later: owner, operator (maintain, cannot read values), auditor (read audit only). A school with several administrators needs these (section 14, D2 / D6).
- **Step-up:** any action that reveals a value, deletes, exports, changes key wraps or changes the bind address needs a fresh sign-in within the last few minutes.
- **Reveal policy (decision D2).** The least risky UI is *write-only*: you can set or replace a value, never read it back. If reveal is allowed at all it is a one-time display after step-up, from loopback only, and audited.
- Session: server-side session, short idle timeout, cookie flags `Secure` (when TLS) / `HttpOnly` / `SameSite=Strict`, CSRF token on every state-changing call, `Host`-header allow-list (defeats DNS rebinding of the loopback port), no CORS.

### 7.4 Attack surface and defaults

| Surface | Default | Why |
|---|---|---|
| Listener | off until enabled; when on, `127.0.0.1` only, random-by-default port | a secrets UI that listens on a LAN or the internet by default is the worst plausible default |
| Remote reachability | **off**; `web.allow_remote` requires TLS (WebHostAnt automatic certificate), a configured DNS name, passkey sign-in, rate limiting through APIAnt, and a visible banner in the CLI that it is on | recommended answer to "may it be reachable from outside the machine by default": **no** |
| Browser extension/other local web pages | blocked by Host and Origin checks | a malicious page the person visits can try `http://127.0.0.1:port` |
| Other local users/processes on the machine | the OS-bound key and file ACL protect the store file; the UI's port can be probed by any local process, so sign-in is required even on loopback | stated limit: same-user malware wins |
| Dependencies | few; audited by `cargo deny` and `cargo vet`-style review in CI | the UI is the largest code surface |
| Secret values in the browser | none by default (write-only) | removes shoulder-surfing, history/cache, extensions, screenshots |

Whether passkeys work against a `localhost` origin and which browsers allow WebAuthn on plain `http://127.0.0.1` is **UNVERIFIED** and must be tested early, since it decides whether loopback needs TLS too.

### 7.5 Audit: AuditAnt

Every sign-in (success/failure), reveal, put, rotate, delete, deliver, export, import, config change and key-wrap change is an event: who (identity/consumer), what (name, never value), when, from where (loopback or address), result. AuditAnt is "structured events + append-only tamper-evident audit trail (uses RedactAnt)", name claimed, **not built**. Stub: an append-only line file where each record includes a hash of the previous record. It is replaced by AuditAnt when published. Limit stated: a same-user attacker can truncate or rewrite a local file; tamper-*evidence* needs the chain head saved somewhere the attacker cannot write (an owner-chosen second location), which is a later feature.

### 7.6 Alerts: SentinelAnt and NotificAnt

SentinelAnt ("detection over events (brute force etc.)") consumes the audit events and raises findings such as repeated failed sign-ins, a reveal from a new address, a rotation overdue, a delivery that failed; NotificAnt ("notification policy: severity, routing, de-dup, escalation") routes them over CommunicAnt (email, a desktop notification, a message). Neither is built; until they are, SecretAnt prints alerts to its own log and exposes a "needs attention" list in the UI. The alert text never carries a value or a path to one.

## 8. Bootstrapping a person's SecretAnt in an installer

The requirement is that *every* install of our software sets up SecretAnt for the installer's user (requirement 1).

### 8.1 The shape

1. Our installers (starting with `humboldt-setup`) link or call the `secretant` library through a **step**: `probe` (is there a store for this user?), `plan` (create one / use the existing one), `apply`, `read_back`. This matches the installer's own step engine (`probe, plan, apply, read_back`, section 2 of `INSTALLER-DESIGN.md`).
2. **No store yet:** create it, create the OS-bound wrap, show the recovery key once with a required "I have saved it" confirmation, offer a passphrase, finish.
3. **Store exists** (the person's SecretAnt from another product): use it; never create a second one; add only this product's entries.
4. The installer then writes the product's secrets *into the store* (the Cloudflare token the person typed, the generated `TOTP_ENCRYPTION_KEY`) and uses `deliver` to place them on the host. Today the installer "stores no credential" and holds tokens in memory for one run (section 4 of the installer design). With SecretAnt that changes: the credential may be kept in the person's own store **if they agree**, so `reconfigure` later does not ask again. The installer design must be amended for that; it is a Humboldt-lane change, not made here.
5. The installer's secrets list (`install::SECRETS`, checked against the Worker's `Env` by a test, same document, section 1) becomes the list of names it asks SecretAnt to place.

### 8.2 What the installer must say in plain words

Before first use: "Your secrets are kept on this computer, protected by [Windows/your keychain]. Nobody at Thinker's Journal can open them or reset them. If you lose both this computer and your recovery key, they cannot be recovered; you would create new ones with each service." (This matches the installer design's own lost-access paragraph, section 8.1.)

### 8.3 Constraints

- Installer distribution is blocked on the Humboldt licence and signing decisions (installer design, section 8.3); SecretAnt is `MIT OR Apache-2.0` (Cargo.toml) so it adds none.
- On a school server (Docker target), the store is created for the account that runs the installer, on that server or admin machine, per the school-secrets rule (section 2). The installer must ask *where* before creating it.
- Linking: SecretAnt must build into a single executable on Windows without a system OpenSSL dependency; prefer a pure-Rust crypto stack. The installer design flags `openssl-sys` trouble on the backend crate (**UNVERIFIED** here, quoted as theirs).
- Uninstall never deletes the store.

## 9. Threat model

### 9.1 Attackers

| Attacker | Can they get secrets? | What stops or limits it | What does not |
|---|---|---|---|
| **Stolen laptop, powered off, disk not encrypted** | Store is ciphertext; OS-bound key lives in the user's profile, so with the user's login password offline attacks on DPAPI-style protection apply (**UNVERIFIED** strength) | passphrase wrap with Argon2id; full-disk encryption (we tell the owner to turn it on; `doctor` checks where the OS allows) | a weak or absent login password; no disk encryption |
| **Stolen laptop, unlocked/logged in** | Yes: the attacker is the user | auto-lock, step-up for reveal, short sessions | nothing in software; it is the "same-user" limit |
| **Malware on the host, same user** | Yes (reads the store and asks the OS for the key) | none strong; detect via audit, minimise what is on the machine, hardware-bound wrap (later) | everything; stated plainly in the README, as `with-secret` does |
| **Malware, other user / remote attacker with no login** | No, if the store file ACL and the loopback-only UI hold | file ACLs, loopback bind, Host/Origin checks, sign-in even on loopback | a bug in the UI is a remote code path if `allow_remote` is on |
| **Leaked bootstrap credential** (the one-time web token; a delivery target's API token; the recovery key) | Depends which | token is one-use and expires; delivery tokens are scoped minimal, kept as entries with `rotate_by`; recovery key kept apart from the laptop | a leaked recovery key plus the store file = full compromise. Rotate all and re-key |
| **Malicious administrator** (a school IT person who should not read everything) | Yes if they hold the owner role | roles (operator cannot read), step-up, audit with off-machine chain head, two-person rule for export (later) | an owner-role admin acting alone in v1 |
| **Backup theft** | Ciphertext only; the key is never in the backup | backups encrypted; the export bundle uses a separate passphrase | a backup plus its passphrase; an old backup keeps old secrets (rotate after a theft) |
| **Supply-chain** (a malicious crate, a poisoned build, a fake installer) | Yes, a build that exfiltrates would win | `cargo deny` (already in the repo), `Cargo.lock` pinned, minimal dependency list, reproducible-ish builds, signed releases with checksums (cost is a CireSnave decision, installer design 7.2), egress allow-list test, provenance rule (`CLAUDE.md` section 9: trace every third-party file) | a compromised upstream crypto crate before review; the first install trusting the download |
| **Host compromise at a delivery target** (Cloudflare account, Docker host) | The copies placed there | minimal-scope tokens, `verify` drift, rotation | pushed secrets are readable by the app and so by whoever owns the app's runtime |
| **Shoulder-surfing/screen recording of the web UI** | Only if values are shown | write-only default (D2) | n/a |

### 9.2 What SecretAnt does not defend, in one line

A process running as the same user can read what the owner can. This is the same stated limit ConfigurAnt and `with-secret` publish; SecretAnt's README must repeat it in the first screen.

### 9.3 Recovery when the master key is lost

Honest statement: **some loss is unrecoverable, and we cannot help**, because holding a recovery path ourselves would break requirement 2.

| What was lost | Recoverable? | How |
|---|---|---|
| The OS-bound wrap only (profile reset, new PC) | Yes | passphrase wrap, or recovery key, on the new machine, with the store file |
| Passphrase only | Yes | OS-bound wrap or recovery key |
| OS-bound wrap **and** passphrase **and** recovery key | **No.** The store is permanently unreadable | the owner re-creates each secret with its issuer (rotates every token). SecretAnt can list *names* from an old export's cleartext index only if the owner opted into a cleartext name list (a per-store choice, D5) |
| The store file with no backup | **No** | same |
| The recovery key only, while another wrap still works | Yes, and the owner should issue a new one at once | `keywrap add recovery` |
| An admin leaves a school and was the only holder | Not unless a second holder was set up | the school should hold two wraps/people; the installer asks (D6) |

Offered mitigations, none of which involve us: a second wrap held by a second person at the school; a recovery key split among N people so any K can rebuild it (Shamir secret sharing; **UNVERIFIED** which Rust crate and its audit status); periodic `verify` of the backup (restore test on a throwaway directory, because an unrestored backup is a hope).

### 9.4 Backups

`secretant backup` produces the encrypted store as is. It contains no key. The tool refuses to write the recovery key into the same place as the backup. Restore is tested in CI with a known-bad control (a backup with one flipped byte must fail to open, loudly).

### 9.5 Export and import

- **Export**: an encrypted bundle (own passphrase, not the store key), versioned format, containing entries with versions and metadata, never delivery credentials unless asked. Contains a manifest (names, counts) so import can say what it will do before it does it.
- **Import**: dry-run by default (matches `db-install`'s dry-run-then-confirm habit in the installer design, section 7.3); conflicts by name are shown and resolved explicitly (keep, replace, add as new version); never silently overwrites.
- Open format promise: the bundle format is documented, so a person is never locked in. Importers from 1Password/Bitwarden exports, `.env` files, and `with-secret` are separate adapters; `.env` import warns that the source file is plaintext and offers to shred it.

## 10. Build or adopt

Everything in this table about external products is **UNVERIFIED**: written from general knowledge, with no product documentation read for this note (I did not browse). Treat as a worklist for a proper survey (slice 0), which must read each project's current licence, maintenance state and API before any adoption.

| Option | What it is (as I recall) | Fit for "person's/school's own, no service of ours" | Fit as an adapter/dependency | Verdict (provisional) |
|---|---|---|---|---|
| **age / rage** (file encryption) | small, modern file-encryption format and Rust implementation | excellent: no server | **adopt as the store's encryption** | adopt a primitive |
| **SOPS** (+ age) | encrypts values inside config files, commits ciphertext to git | good for files in repos; not a runtime interface; no rotation tracking, no delivery | possible *import/export* format | interop, not core |
| **OS keychains** (Windows Credential Manager/DPAPI, macOS Keychain, Linux Secret Service, `keyring` crate) | the OS stores small secrets per user | good for holding the *key wrap*; poor for 100s of entries with metadata, versions and exports; behaviour differs per OS | **adopt for key wrap** | adopt for keys |
| **systemd-creds** | systemd feature to encrypt/ pass credentials to services, optionally TPM-bound | good on Linux hosts as a *delivery target* and key wrap | adapter, Linux only | adapter |
| **Windows DPAPI** | per-user/machine key protection | wrap, not store | adapter via OS layer | adapter |
| **OpenBao** (open-source Vault fork) | server with access policies, dynamic secrets, audit | powerful; someone must run and unseal a server (heavy for a person); a school's IT might already | optional remote client (4.5) | adapter, later |
| **HashiCorp Vault** | same lineage; licence changed to a source-available one in 2023 as I recall | same | avoid as dependency (licence); client to Vault-compatible API only | at most a client |
| **Infisical** | open-source secrets manager with a hosted option and a server you can run | convenient UI and syncs to hosts (similar to our push idea) | optional client; or a competitor shape to study | study, adapter maybe |
| **Doppler** | hosted secrets service, syncs to hosts | secrets sit in *their* service, a third party's; allowed by requirement 2 only if the owner chooses it, never as our default | optional client | adapter at most |
| **1Password Connect / service accounts** | existing password-manager vaults with machine access | many people already own one; secrets in a third party's cloud by their choice | optional client | adapter, later |
| **Bitwarden Secrets Manager** | similar | similar | similar | not first |
| **Cloud secret managers** (Cloudflare Secrets Store, AWS/GCP/Azure) | host-native | they are *targets* | delivery targets | targets |
| **Docker/Compose/Kubernetes secrets** | host-native placement | the installer's Docker target | delivery targets | targets |

**Recommendation: build the thin orchestration, adopt the primitives.** Build: the entry model (names, versions, metadata, bindings), the policy and audit hooks, the delivery plans and drift checks, the ConfigurAnt adapter, the installer step, the web UI. Adopt: an existing audited encryption format/library, the OS keychain access, and existing remote vaults as optional clients. No existing option in the table was found, from what I recall, to cover "a person-owned store that also delivers to Cloudflare/Docker/files and is configured the way our other tools are"; that is also exactly the claim to test in the survey and in the patent sweep (section 13). A "no, adopt SOPS+age only" is a live alternative (D3, option B).

## 11. Dependency order

| Needed | State (read in `PORTFOLIO-ROADMAP.md` Ant table, 2026-10-28 or earlier) | Must exist first? | Stub if not |
|---|---|---|---|
| **ConfigurAnt** | core published (0.2.25 at the time `SECRET-SOURCES.md` was written); `configurant-secrets` with the `SecretSource` trait built but its publish state **UNVERIFIED** | Yes, exists | none needed |
| **CapAnt** | design phase 0.0.7 (README) | No | a hard-coded adapter list with the same trait names; swap later |
| **RedactAnt** | name queued, not built | No | small private type behind a trait (3.5) |
| **AuditAnt** | name claimed, not built | No | hash-chained append-only file (7.5) |
| **PersistAnt** | built, published 0.9.10 | Optional | plain atomic file |
| **BedrockAnt / OS layer** | survey assigned; name not claimed | Preferable for slice 2 | write the three OS calls (DPAPI, Keychain, Secret Service) in a private module, planned to move |
| **user-request / consent** | exists in `ciresnave/consent` per OverMind spec; publish state **UNVERIFIED** | for Hello step-up only | OS prompt behind a trait; or none in v1 |
| **HTTPAnt** (core + server) | confirmed, repo to move; not built | for the web UI | thin local server behind its trait |
| **APIAnt** | name claimed | for the web UI's API | hand-wired routes |
| **WebHostAnt** | reserved name, nothing built; wants the installer first and a design note | for the web UI | run the UI with a minimal loopback server, no TLS, no remote |
| **AuthAnt** | built under the old name, rename in progress | for multi-user sign-in | passkey via consent/OS only |
| **SentinelAnt / NotificAnt / CommunicAnt** | names queued/claimed, not built | no | log + "needs attention" list |
| **ReleaseAnt** | design phase | only for publishing | manual |

Order implied: core + local store + CLI have **no unbuilt prerequisites** and can start the moment the design is approved. The web interface cannot be finished before HTTPAnt/WebHostAnt exist and so is deliberately last (requirement 3 wants it hosted via WebHostAnt, and WebHostAnt's roadmap waits on the installer).

## 12. Effort slices

Sizes: S = a few days, M = 1-2 weeks, L = several weeks. All are guesses (**UNVERIFIED**). One PR each; known-bad tests first; each slice is a version bump and none is published until the PM decides.

| # | Slice | Size | Needs |
|---|---|---|---|
| 0 | Survey of the table in section 10 (read the docs) + patent sweep queries (section 13) + decisions D1-D8 | S-M | CireSnave |
| 1 | Core model, local encrypted store (age-style), versions/metadata, library API, `secretant` CLI (`put/get/list/rotate/run`), canary + negative-control tests, private Redact/Audit stubs | L | 0 |
| 2 | OS key wraps (Windows DPAPI first, then macOS, Linux), recovery key + passphrase wraps, permissions/ACL | M-L | 1 |
| 3 | ConfigurAnt: SecretAnt's own schema; `secretant:` adapter crate; cycle check; docs row in ConfigurAnt | S-M | 1, ConfigurAnt on crates.io |
| 4 | Delivery: file/Docker secrets, environment; plan/apply/verify/drift | M | 1 |
| 5 | Delivery: Cloudflare Worker secrets (check API availability first) and other hosts | M each | 4 |
| 6 | Export/import, backup, restore test, recovery-key flow, `doctor` | M | 1, 2 |
| 7 | Installer step library + docs; Humboldt installer change request | S here, M in Humboldt | 2, 6 |
| 8 | Real RedactAnt/AuditAnt adoption when published | S | those |
| 9 | Optional pull mode: local agent, consumer policy, timeouts | M | 1, 2 |
| 10 | Web interface: read-only status first, then write operations; step-up; CSP; Host checks | L | HTTPAnt, WebHostAnt, 3 |
| 11 | Alerts via SentinelAnt/NotificAnt | S | those |
| 12 | Remote vault client adapters (one per product) | M each | 1 |
| 13 | `with-secret` convergence (store behind its gate) | M | its design read, D8 |

First useful release for CireSnave: slices 1, 3, 4 and part of 6 (store, ConfigurAnt, push to file/env/Docker, export). Installer bootstrap (7) follows the first Humboldt installer slice.

## 13. Patent sweep: queries to run later

Per `PATENT-SWEEP-PROCESS.md` the sweep is a documented search and claim-by-claim read, run by a lane before any release with functionality; nothing here is cleared. Ideas to sweep: (i) one personal store with versions and metadata driving delivery to several host-native stores; (ii) key wrapping with multiple independent unlockers and a recovery key; (iii) installer-time provisioning of a per-user secret store; (iv) configuration-schema references that resolve secrets by reference without values appearing in configuration; (v) local web management interface with write-only secret entry. Queries (Google Patents, USPTO, Espacenet, WIPO; record date and source for each):

1. `secret management "deploy" "host" "secret store" "synchronize" credentials to cloud function environment`
2. `"credential vault" "version" "rotation" "delivery target" push secrets to multiple hosting environments`
3. `"master key" "wrapped" "recovery key" "plurality of key encryption keys" secret store`
4. `installer "provisioning" "secure store" user credentials "during installation" "operating system keystore"`
5. `configuration file "reference" to secret "resolved at load time" "does not contain" secret value schema`
6. `web interface "write-only" credential entry "step-up authentication" secrets administration loopback`
7. `drift detection secret deployed copy "fingerprint" without revealing secret value compare`
8. `local credential store "operating system" keychain DPAPI "encrypted file" cross-platform secret retrieval application`
9. `secret rotation "staged" "old version" "new version" overlap window deployment credentials`
10. `"split" recovery key "threshold" "secret sharing" personal credential store backup`

Also search the owner-names behind the products in section 10 (HashiCorp, Infisical, Doppler, 1Password) as assignees. Not legal advice; no attorney exists (repo `PATENT-SWEEP.md`).

## 14. Decisions for CireSnave

Each in plain words, with a recommendation. "Store" means the encrypted file holding someone's secrets.

**D1. How should a secret normally get from SecretAnt to the program that needs it?**
- A. SecretAnt copies ("pushes") the secret into the place where the program runs (the host's own settings, a protected file, a Docker secret) when the program is installed or updated. The program never contacts SecretAnt. Simple and works even when the store sits on a laptop and the program runs on Cloudflare; the cost is that changing a secret means pushing again. (Recommended.)
- B. The program asks SecretAnt each time it starts ("pull"). Changes arrive automatically, but the program needs a login to SecretAnt (which itself must be delivered somehow), the store must be reachable and running, and a stolen program login can read more.
- C. Support both as equals with no default. Most flexible, but every install has to ask a question most people cannot answer.

**D2. Should the web interface ever show a stored secret back to you?**
- A. Never: you can add or replace a secret but not read it. Safest against screen capture, browser extensions and shoulder-surfing; to see one you use the command line. (Recommended.)
- B. Only once, after signing in again, from the same computer, with a log entry.
- C. Whenever you are signed in, including remotely. Easiest and the most dangerous.

**D3. Do we build the store ourselves or adopt an existing tool?**
- A. Build the thin part (names, versions, delivery, setup, interface) and adopt proven building blocks for encryption and the operating system's key storage; offer existing vaults as optional connections. (Recommended.)
- B. Adopt SOPS plus age only and build nothing but glue; least work, but no delivery tracking, no web interface, no installer story.
- C. Adopt a vault server (OpenBao or Infisical) as the store. Powerful, but a person has to run a server, which conflicts with "one place they control" for an ordinary person.

**D4. How do we read "a school's secrets stay with the school" when the school uses a service we run?**
- A. Strict reading: credentials a school holds for its own other systems never reach us; the secrets a service of ours needs to run are held in that service, and a school that wants them out of our hands installs its own copy (the Humboldt installer). Tell schools this in plain words. (Recommended.)
- B. Stricter: we do not run any service holding school data at all (the installer is the only way). This ends our hosted option.
- C. Looser: allow school secrets in our hosting if the school opts in. Contradicts what you wrote; I advise against.

**D5. May a store keep a readable list of secret NAMES (not values) next to the encrypted data?**
- A. No: even names are encrypted; if everything is lost, nothing about it is learned. (Recommended default.)
- B. Optional per store: a readable list of names makes disaster recovery easier (you know which tokens to re-issue) but tells a thief which services you use.
- C. Always keep one.

**D6. What should the installer require so a lost key does not mean lost secrets?**
- A. A recovery key shown once, with a required confirmation that it was written down, and a prompt for a second holder for schools. (Recommended.)
- B. Optional recovery; the installer only warns.
- C. No recovery at all; a lost key means starting over. Most private and harshest.

**D7. Which order: command-line first, or web interface first?**
- A. Command line and library first, web interface last (because WebHostAnt and HTTPAnt do not exist yet and the web interface is the largest attack surface). (Recommended.)
- B. Build a small web interface first on a temporary server and switch to WebHostAnt later; faster to look at, but we build it twice.
- C. Wait for WebHostAnt and do everything at once; slow.

**D8. Where does the ConfigurAnt connector live, and does `with-secret` eventually sit on SecretAnt?**
- A. Separate small connector crate; `with-secret` keeps its own vault for now and moves onto SecretAnt only after its authors' design has been read and a migration is agreed. (Recommended.)
- B. Connector inside SecretAnt as an optional feature; same `with-secret` plan.
- C. Replace `with-secret`'s vault with SecretAnt right away. Fastest unification; risks breaking the thing that currently keeps secrets away from the agent fleet.

