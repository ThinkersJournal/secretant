# SecretAnt lane HANDOFF

Rewritten 2026-11-16T18:30Z by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. `origin/main` 4af2e71 = 0.1.3 (rows 1-8 merged; #36 ROADMAP status plus truncated-bundle test merged 2026-11-16). crates.io has 0.0.2 (placeholder, 2026-11-10) and 0.0.0; nothing newer published or tagged. PM publishes and tags; the lane never does.
- Main CI: all required jobs green; `portfolio` red only on SEC-002 (false positive at CHANGELOG.md:5, advisory, not required; do not reword).
- Sent [READY] publish-0.1.0 readiness to the PM 2026-11-16. Open question for the PM: README says "this is 0.1.0" but Cargo.toml is 0.1.3; the PM allocates the version to publish.
- PM owns before publish: live Cloudflare run (board 448, waits on CireSnave), SEC-002 ruling, patent-database search or CireSnave decision, no-echo passphrase check (the lane ran the stdin/env round trip on Windows and WSL: pass), consumer verification (ConfigurAnt adapter, WebHostAnt C7b with a temporary `[patch]`), publish, tag `v0.1.x`.
- Known unverified claims: "wiped on drop" has no test (relies on redactant/zeroize); algorithm names proved by code reading only; the Unix owner-only test was not run by the lane.
- webhostant C7b needs: `SecretValue` unchanged, `SecretReader::{open(ReadConfig),get,list}`; consumers need a wildcard arm on the `#[non_exhaustive]` enums.
- Stale worktrees (clean before removing): secretant-wt-lane (old HANDOFF), secretant-wt-docs2 (this branch), secretant-wt-row1-store, secretant-wt-docs, secretant-wt-design.

WAIT: pm-publish-0.1.x | check: gh api repos/ThinkersJournal/secretant/tags --jq .[].name | wake: 2026-11-17T12:00:00Z

## Tasks held
1. Nothing unblocked. Rows 9 (no test env), 10 (needs ConfigurAnt on crates.io), 11 (needs RedactAnt/AuditAnt) stay blocked. Do not invent work; ask the PM. If asked: re-run the fresh-eyes trial at the version to publish (`tools/fresh-eyes-trial.sh`).

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day (CireSnave 2026-11-16) unless the PM orders otherwise. Write Windows files with the Write tool or a file, not a bash heredoc holding quotes; python string edits: raw strings for regexes. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. Force-push is denied: merge `origin/main` into open PR branches. One changelog fragment per PR (PM stamps versions). Ack every synapse message; message values have no spaces. Deleting remote branches needs the PM. WSL (Ubuntu-24.04) has cargo; its git cannot read a Windows worktree, so copy the `git ls-files` list into a Linux directory to build there.
