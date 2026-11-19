# SecretAnt lane HANDOFF

Rewritten 2026-11-19 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. secretant 0.1.6 published. Cluster PM pm-ants; [READY] to pm-assist cc pm-ants (C:\Projects\LANE-REPORTING.md). Synapse online.
- PR #40 (branch lane/secretant-d2, head 0e08d24, worktree secretant-wt-lane): row 10 schema + cycle check, row 9 probe PASSED both OSes (ROADMAP dated), MSRV 1.95. 12/12 checks green. [READY] sent. pm-assist HOLD: second PR of 11-19; it releases 2026-11-20T00:00Z as 0.2.0 and deletes the branch itself.
- Row 11: RedactAnt already adopted; AuditAnt is a 0.0.0 placeholder, blocked on its lane.
- Known unverified: "wiped on drop" has no test; the Unix owner-only test was not run by the lane.
- Stale worktrees (clean before removing): secretant-wt-row1-store, secretant-wt-docs, secretant-wt-design, secretant-wt-docs2.

## Tasks held
1. Wait for #40 to merge (pm-assist, after 2026-11-20T00:00Z). Do not push to its branch.
2. Row 9 slice 1 (macOS Keychain / Linux Secret Service wraps; tests run on the macos-latest and ubuntu-latest setups from os-store-probe.yml, never #[ignore]) on a fresh branch off origin/main once #40 is merged; read DESIGN section 4 wraps and src/store.rs first. One PR per day: open it 2026-11-20 or later.

WAIT: PR 40 merged | check: gh pr view 40 --json state,mergedAt | wake: 2026-11-20T00:30:00Z

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Ack every synapse message; message values have no spaces.
