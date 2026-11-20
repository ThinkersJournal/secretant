# SecretAnt lane HANDOFF

Rewritten 2026-11-20 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. main 0.2.1 (#40 0.2.0 Breaking: MSRV 1.95, os-keystore; #41 EasyAnts card, merged 2026-11-20T00:50Z). crates.io still 0.1.5: the PM publishes. easyants told of the card merge. Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane is on fresh branch lane/secretant-d4 (origin/main). Stale worktrees removed 2026-11-20. Remote lane/secretant (old branch) still exists: gate or PM deletes. Many old local lane/* branches remain (merged long ago): prune only after checking each with `gh pr list --head`.
- Row 9 slice 1 merged (Keychain, dbus Secret Service). Row 10 done. Row 11: AuditAnt is a 0.0.0 placeholder.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane.

## Tasks held
1. Next PR opens 2026-11-21 UTC or later (one per day). Slice: README keeps the 0.2.0 Breaking note prominent until published (pm-ants); then systemd-creds wrap; CLI and installer exposure of the OS wrap (`--os` on non-Windows with the os-keystore feature). Tests on real stores via .github/workflows/os-store-probe.yml.
2. Work and commit on lane/secretant-d4 meanwhile; do not open the PR before 11-21.

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Do not push HANDOFF-only commits to an open PR (reruns CI). Ack every synapse message; message values have no spaces.
