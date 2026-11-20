kind: EasyAnts card and a runnable quickstart example
---
Adds `easyants-card.toml` (status `ready`, read by the EasyAnts hub per its `docs/CARD-FORMAT.md` @12844fd) and `examples/quickstart.rs`, the seven-line excerpt the card shows: create a store, put a secret, read it back through `SecretReader`, assert the value. Cargo builds it with `--all-targets` in CI and it was run locally (exits 0). The card makes no claim about the macOS and Linux key wraps. No library change.
