# SecretAnt

One place, controlled by its owner, where a person or school keeps their secrets. Status: early (0.0.x), not yet released with functionality; see ROADMAP.md.

**Same-user limit, stated first:** SecretAnt keeps a store file private to its owner and encrypted at rest. It does not defend against another
program running as the same user: such a program can do what SecretAnt's own read API does. It also has no recovery path of ours: lose every way
of opening the store and the secrets are gone.

Built so far: an opaque secret value type, a local encrypted file store with versions, three ways to open it (passphrase, recovery text, Windows
user account), and a read API for adapters (`SecretReader`) with four error classes and a timeout on every call.
