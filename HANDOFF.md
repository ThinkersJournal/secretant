# SecretAnt lane HANDOFF

Rewritten 2026-11-25 00:20Z by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane on branch lane/secretant-d7 (holds untracked .releaseant/ and supertool, so not removed). pm-assist pushed the 0.2.5 stamp (b0713837) onto it: pull, no force.
- **PR #45 OPEN** (vault tool: secretant-mcp, rmcp shim, host binary, Hello approver on SecretPlacement/OneUse). Diff 132,076 chars. [READY] sent to pm-assist, STATUS to pm-ants; pm-assist ARMED the merge (waits on checks). Hello approver is fake-tested only (needs the human at the desktop). run_with_secret is out of slice 1.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane. easyants-card.toml pins `cargo add secretant@0.2.1`.
- Remote lane/secretant (old, fcbd0a5) is audited safe-to-delete; delete was denied by the classifier: needs the user. Do not delete it yourself.

## WAIT
1. PR #45 merge: check `gh pr view 45 -R ThinkersJournal/secretant --json state`. If checks go red or the portfolio advisory shows new Mediums, fix on lane/secretant-d7 (disposition Mediums on the PR). After merge: delete the remote branch (section 3 recipe), `git worktree remove` only if clean (untracked .releaseant/ and supertool block it: ask), start a fresh branch.
2. Next rows: none unblocked. Candidates: a "wiped on drop" test; run_with_secret design note (to pm-ants first, not code).

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Gates before [READY]: fmt, clippy default and --all-features, `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also --all-features), deny, tests. One changelog fragment per PR. Ack every synapse message; message values have no spaces.
