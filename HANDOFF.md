# SecretAnt lane HANDOFF

Rewritten 2026-11-21 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. main 0.2.2 (PR #42 merged 2026-11-21, main=01586b8; gate stamped 0.2.2, deleted branch lane/secretant-d4). Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane is on fresh branch lane/secretant-d5 (origin/main 01586b8). Primary C:\Projects\secretant is at f65d637 (behind main; sync-checkouts fast-forwards it). Remote lane/secretant (old branch) still exists. Many old local lane/* branches remain (merged long ago): prune only after checking each with `gh pr list --head`.
- Row 9 slice 1 merged (Keychain, dbus Secret Service). Row 10 done. Row 11: AuditAnt is a 0.0.0 placeholder.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane.

## Tasks held
1. systemd-creds wrap: BUILT and committed on lane/secretant-d5 (8323c48, pushed to origin/lane/secretant-d5, no PR yet): `os::systemd_creds` (Linux + os-keystore; `systemd-creds --user encrypt/decrypt --name=secretant-os-wrap - -`, stdin/stdout only), fallback in `add_os_wrap`, kind `os-systemd-creds` in `try_wrap`, test `systemd_creds_wrap_round_trips_and_a_damaged_blob_does_not_open`, CI job `systemd-creds` in os-store-probe.yml (replaced the probe), docs/FORMAT.md, README, ROADMAP row 9, fragment changelog.d/systemd-creds-wrap.md. Windows: fmt, doc, tests --all-features pass. The Linux code now COMPILES and is clippy-clean (default and --all-features, -D warnings) in WSL: `wsl -d Ubuntu-24.04 -- bash -lc 'cd /mnt/c/Projects/secretant-wt-lane && CARGO_TARGET_DIR=/root/secretant-tgt RUSTC_WRAPPER= cargo clippy ...'` (checked 2026-11-21; Windows cross-check fails on aws-lc-sys). Still untested at runtime: the `systemd-creds` stdin/stdout form (WSL systemd 255, no --user); workflows run only on pull_request. Next: after 2026-11-22 00:00Z open ONE PR from d5, read the `systemd-creds` and `linux-secret-service` jobs by name (a compile error or a wrong `systemd-creds` stdin/stdout form shows there), fix, run clippy default and --all-features, deny, then [READY] to pm-assist cc pm-ants. `--user` needs systemd 256+ (local WSL has 255, cannot test).
2. Remote lane/secretant (old branch, fcbd0a5) is audited safe-to-delete; delete was denied by the classifier: needs the user. Do not delete it yourself.

Soft-stopped 2026-11-21 at pm-ants' request (image job memory); PM wakes by mail, no cron. On wake: run `lane-restart waits`, re-arm the WAIT, continue task 1.

Soft-stopped 2026-11-21 at pm-ants' request (CPU 100%, EXPECTATIONS 6.32); pm-ants wakes by mail at 00:02Z for the PR window. No WAIT, no cron. On wake: open the ONE PR from lane/secretant-d5 (task 1), then read CI jobs.

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Do not push HANDOFF-only commits to an open PR (reruns CI). Ack every synapse message; message values have no spaces.
