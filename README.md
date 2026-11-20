# SecretAnt

One place, controlled by its owner, where a person or school keeps their secrets: an encrypted file store with versions, a read API for programs, a command line, and delivery of values to files, environment files and (feature `cloudflare`) Cloudflare Workers. Status: pre-1.0; the first line of releases with functionality.

**Same-user limit, stated first:** SecretAnt keeps a store file private to its owner and encrypted at rest. It does not defend against another
program running as the same user: such a program can do what SecretAnt's own read API does. It also has no recovery path of ours: lose every way
of opening the store and the secrets are gone.

**0.2.0 is a breaking release (pre-1.0, so the second number):** the minimum Rust version rises from 1.88 to 1.95. It also adds the off-by-default feature `os-keystore`, which lets `Unlock::Os` and `FileStore::add_os_wrap` use the macOS Keychain and the Linux Secret Service as well as Windows DPAPI (`cargo add secretant --features os-keystore`). Until 0.2.x is on crates.io, `cargo add secretant` gives 0.1.5.

## Ten lines

Add the crate, and `tempfile` too: the example keeps its store in a throwaway directory (a real program would not need `tempfile`).

```sh
cargo add secretant
cargo add tempfile
```

`cargo add` may print `Features: - cloudflare`: that lists the optional Cloudflare feature, which stays **off** unless you ask for it (`cargo add secretant --features cloudflare`).

The two lines starting `# ` below are hidden on rendered pages; they wrap the example in `fn main() -> Result<(), Box<dyn std::error::Error>>` and create that directory.

```rust
use secretant::{FileStore, KdfParams, ReadConfig, ReadUnlock, SecretReader, SecretValue, Store};
use std::{collections::BTreeMap, time::Duration};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let dir = tempfile::tempdir()?;
let path = dir.path().join("store.json");
let pass = || SecretValue::from_string("a long passphrase".into());
// Cheap costs, for this example only: `FileStore::create` has safe defaults.
let cheap = KdfParams { m_kib: 64, t: 1, p: 1 };
let mut store = FileStore::create_with_params(&path, &pass(), cheap)?;
store.put("API_TOKEN", SecretValue::from_string("s3cret".into()), BTreeMap::new())?;

let config = ReadConfig { path, unlock: ReadUnlock::Passphrase(pass()), timeout: Duration::from_secs(10) };
let reader = SecretReader::open(config)?;
assert_eq!(reader.get("API_TOKEN")?.expose(), b"s3cret");
# Ok(())
# }
```

The same from the command line (the value is read from standard input or the terminal, never an argument):

```sh
secretant init                       # asks for a new passphrase, twice, no echo
echo -n 's3cret' | secretant --passphrase-env put API_TOKEN
secretant run API_TOKEN -- my-program   # the value is in the program's environment only
```

`secretant --help` lists every command: `init put rotate get list run backup restore-test restore doctor export import deliver cloudflare`.

## What is in it

- `SecretValue`: no `Display`, `Clone` or `Serialize`, `Debug` shows nothing, wiped on drop.
- `FileStore`: XChaCha20-Poly1305 under a random data key; wraps by passphrase (Argon2id), recovery key and Windows user account each open the same key; atomic writes with one previous generation; owner-only file.
- `SecretReader` (open, get, list names): four error classes (`NotFound`, `Denied`, `Unreachable`, `TimedOut`) and a timeout on every call, for adapters.
- Backup, restore, `doctor`, export and import bundles; delivery plan, apply and verify to files and environment files with a ledger of what was placed where.
- The installer step library (`secretant::installer`, `secrets_step`, `place_step`): pre-1.0, **may change in 0.2**.
- Cloudflare Worker delivery (feature `cloudflare`): **tested against a fake of Cloudflare's documented API only; it has not been run against the live service yet.**

## What it does not do

- **Cloudflare delivery is not proven against the live service.** It is tested against a fake of Cloudflare's documented API only (feature `cloudflare`, off by default). Treat it as unverified until a release says it was run live.
- **No audit.** SecretAnt keeps no record of who read a secret; the delivery ledger records what was placed where, not who asked.
- **OS-bound wraps are Windows only.** The Windows user-account wrap (DPAPI) is in; macOS and Linux OS wraps come later. Passphrase and recovery-key wraps work everywhere.
- **No defence against the same user.** Another program running as you can do what SecretAnt's own read API does (see the limit at the top).
- **The hidden-prompt entry (no echo) is not tested through a real terminal on Windows or WSL.** CI has no terminal; the `--passphrase-stdin` and `--passphrase-env` paths are tested and were run by hand on Windows and WSL, the no-echo prompt was not.
- **Not here yet:** a web interface and remote vaults.
- **The installer modules may change in 0.2** (`installer`, `secrets_step`, `place_step`).

**Dependencies.** The default build has **50 packages** in its normal dependency tree (`cargo tree -e normal --prefix none | sed 's/ .*//' | sort -u | wc -l`)
and no HTTP or TLS crate. Cloudflare Worker delivery is the cargo feature `cloudflare` (off by default; it adds an HTTP client and the TLS stack under it).
A CI job fails if the default tree gains any of those crates; when the number above changes, change it in the same pull request so growth is a visible diff.

Licence: MIT OR Apache-2.0.
