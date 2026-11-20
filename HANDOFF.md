# SecretAnt lane HANDOFF

Rewritten 2026-11-20 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. main 0.2.1 (#40 0.2.0 Breaking: MSRV 1.95, os-keystore; #41 EasyAnts card, merged 2026-11-20T00:50Z). PM published 0.2.1 (tag v0.2.1; 0.2.0 never published). easyants told of the card merge; configurant told of 0.2.1. Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane is on fresh branch lane/secretant-d4 (origin/main). Stale worktrees removed 2026-11-20. Remote lane/secretant (old branch) still exists: gate or PM deletes. Many old local lane/* branches remain (merged long ago): prune only after checking each with `gh pr list --head`.
- Row 9 slice 1 merged (Keychain, dbus Secret Service). Row 10 done. Row 11: AuditAnt is a 0.0.0 placeholder.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane.

## Tasks held
1. Branch lane/secretant-d4 (pushed, 2 commits ahead of main, fragment changelog.d/os-wrap-installer.md): README states 0.2.1 Breaking vs 0.1.5, card snippet `cargo add secretant@0.2.1`, OS wrap in installer and CLI (OS_WRAP_SUPPORTED). Local gates green. Open the PR on 2026-11-21 UTC or later (one per day: #41 opened 11-20), then [READY] to pm-assist cc pm-ants; the macos-keychain and linux-secret-service jobs must run the installer test.
2. Then: systemd-creds wrap (not started). If main moved, merge origin/main into d4 first.

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Do not push HANDOFF-only commits to an open PR (reruns CI). Ack every synapse message; message values have no spaces.
