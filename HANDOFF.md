# SecretAnt lane HANDOFF

Rewritten 2026-11-21 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. main 287e5ed (PR #43 systemd-creds wrap merged 2026-11-22T01:57Z; remote branch d5 gone, local d5 deleted). Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane is on fresh branch lane/secretant-d6 (origin/main 287e5ed); it holds untracked .releaseant/ and supertool, so it was not removed. Primary C:\Projects\secretant is behind main (sync-checkouts fast-forwards it). Many old local lane/* branches remain: prune only after `gh pr list --head`.
- Row 9 done (Keychain, dbus Secret Service, systemd-creds). Row 10 done. Row 11: AuditAnt is a 0.0.0 placeholder.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane.

## Tasks held
1. [TASK] from pm-ants 2026-11-22: claim-to-command audit of README/docs with the real CLI. DONE on lane/secretant-d6 (fragment changelog.d/cli-audit.md): fixes `--os`/`restore` help and README version paragraph. Open the PR, [READY] to pm-assist cc pm-ants, STATUS to pm-ants (published 0.2.1; README now describes 0.2.x; main is 0.2.3, so publish 0.2.3 after this merges stamps its number). Reported: cloudflare read-not-run; no-echo prompt and macOS/Linux paths read-not-run; easyants-card.toml still pins `cargo add secretant@0.2.1`.
2. Remote lane/secretant (old branch, fcbd0a5) is audited safe-to-delete; delete was denied by the classifier: needs the user. Do not delete it yourself.

After the PR merges: delete branch, remove nothing (worktree holds untracked .releaseant/ and supertool), start a fresh branch. No row left: `lane-restart stop --role secretant --self --soft --reason "no live work"` from PowerShell.

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Do not push HANDOFF-only commits to an open PR (reruns CI). Ack every synapse message; message values have no spaces.
