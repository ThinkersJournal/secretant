kind: CI builds on the declared minimum Rust version
---
New CI job "Builds on the declared minimum Rust version": it reads `rust-version` from `Cargo.toml` (so the promise and the check cannot drift), installs that toolchain and runs `cargo check --locked --all-targets` with default features and with all features; it fails if `Cargo.toml` declares none. No code change. Verified locally on 1.88.0 (both checks pass).
