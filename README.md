# SecretAnt

One place, controlled by its owner, where a person or school keeps their secrets. Status: early (0.0.x), not yet released with functionality; see ROADMAP.md.

**Same-user limit, stated first:** SecretAnt keeps a store file private to its owner and encrypted at rest. It does not defend against another
program running as the same user: such a program can do what SecretAnt's own read API does. It also has no recovery path of ours: lose every way
of opening the store and the secrets are gone.

Built so far: an opaque secret value type, a local encrypted file store with versions, three ways to open it (passphrase, recovery text, Windows
user account), and a read API for adapters (`SecretReader`) with four error classes and a timeout on every call.

**Dependencies.** The default build has **42 packages** in its normal dependency tree (`cargo tree -e normal --prefix none | sed 's/ .*//' | sort -u | wc -l`)
and no HTTP or TLS crate. Cloudflare Worker delivery is the cargo feature `cloudflare` (off by default; it adds an HTTP client and the TLS stack under it).
A CI job fails if the default tree gains any of those crates; when the number above changes, change it in the same pull request so growth is a visible diff.
