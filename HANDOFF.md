# SecretAnt lane HANDOFF

Rewritten 2026-11-23 by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. main f81a0a8 (PR #44 claim-to-command audit merged, gate-stamped 0.2.4; remote branch deleted). Cluster PM pm-ants; [READY] to pm-assist cc pm-ants.
- Worktree secretant-wt-lane is on fresh branch lane/secretant-d7 (origin/main f81a0a8); it holds untracked .releaseant/ and supertool, so it was not removed. Primary C:\Projects\secretant is behind main (sync-checkouts fast-forwards it). Old local lane/* branches remain: prune only after `gh pr list --head`.
- Row 9 done (Keychain, dbus Secret Service, systemd-creds). Row 10 done. Row 11: AuditAnt is a 0.0.0 placeholder.
- Known unverified: "wiped on drop" has no test; Unix owner-only test not run by the lane. Audit reported read-not-run: cloudflare, no-echo prompt, macOS/Linux paths; easyants-card.toml pins `cargo add secretant@0.2.1`.

## Tasks held
1. Vault tool (board 498 A, PM TASK below). Design accepted by pm-ants with 3 conditions (a: interim gate = host role prefix scope + allow-list, refuse with no role; b: run_with_secret OUT of slice 1, separate note first; c: allow root refused unless host declares agent-unreadable; junction/symlink tests; Windows ACL). Slice 1 BUILT and pushed on lane/secretant-d7: crates/secretant-mcp (Face: list_names, ledger_read, verify_placement, deliver; PlacementApprover trait; Face::call JSON entry), Ledger::entries in secretant, tests/no_value.rs (canary red-proven by two mutations). Gates green (fmt, clippy both, doc, deny, tests). No PR yet (rides next window; no pin line until 0.48.1 SHA).
   DONE 7dd5bd0 (pushed): stdio shim crates/secretant-mcp/src/serve.rs (feature stdio, rmcp =3.11.0, approved by pm-ants: mcpant was the plan but crates.io has only 0.0.0; say so in the PR) + tests/wire.rs (rmcp-layer no-value test, red-proven; rmcp echoes client-typed method name in -32601, the one allowed echo).
   DONE per pm-ants TASK (pushed f56a34b): item1 subject parser 2abbe0c; item2 exact-case canonical path + recheck 2fab7b8; items 3-5 INTERIM_GATE named+recorded, roots fail closed, owner-only ACL/mode ca24427 (4,5 green on arrival, pinned); doc-link fixes 2b60253,f56a34b. Item 6 (no run_with_secret) already true.
   WAIT (named, swap only): user-request 0.17.0 with KindId::SecretPlacement (overmind, consent 2d00b1f); until then Secret kind behind PlacementApprover.
   DONE 381e336 host binary secretant-mcp --config (DenyAll approver: deliver refused), f6b7874 README. Pushed.
   DONE 821a3e9: Hello approver (feature hello; with-secret 0.16 identity::resolve + user-request 0.16 Secret kind, 120s grant/60s wait, fail closed denied when unplaced; fake-consent tests only, NOT run against a real Hello prompt: needs the human). Subject cap now 64+4+120 so the prompt (clips at 200) shows it whole.
   NEXT NOW: open ONE PR in the 11-25 window (text: name INTERIM_GATE, mcpant->rmcp reason, Cargo.lock + version stamp for pm-assist, deliver refused until approver).
   (old) host binary `secretant-mcp` (host config JSON file owned by the human; Unlock::Os, never a passphrase arg) (ii) Windows Hello PlacementApprover over user-request 0.11.1 Secret kind, shortest grant, strict `NAME -> path` subject parser, exact-case path, length cap, show path whole. (iii) README/threat docs. Later: KindId::SecretPlacement (consent 0.12.0, via pm-ants, do not mail consent lane).
   Note: Cargo.lock changed (new member) and secretant-mcp version is a literal 0.2.4 (publish = false): gate must stamp both.
- Remote lane/secretant (old branch, fcbd0a5) is audited safe-to-delete; the delete was denied by the classifier: needs the user. Do not delete it yourself.

## WAITS (named; mail wakes the lane)
1. Vault-tool PR: lane/secretant-d7 (head f2e3c7c, all slices pushed) opens in the 11-25 PR window; pm-ants mails the wake about 00:12Z. Check: `gh pr list -R ThinkersJournal/secretant`. Then open ONE PR (text: INTERIM_GATE named, mcpant->rmcp reason, with-secret dependency reason, Cargo.lock + version stamp for pm-assist, Hello fake-tested only); do not wait for a reply.
2. (DONE f2e3c7c) SecretPlacement swap: crates.io user-request max_version >= 0.17.0 AND KindId::SecretPlacement in request.rs at that tag (consent#21 open; PM publishes after the gate; pm-ants mails the swap row). Until then Secret kind behind PlacementApprover.

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Sonnet only. Never `gh auth switch`. Sign PR text `— lane: secretant`. One PR per project per day. Write Windows files with the Write tool. Run `RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps` (also `--all-features`), clippy default and `--all-features`, fmt, deny and the tests before [READY]. One changelog fragment per PR. Ack every synapse message; message values have no spaces.

## PM TASK 2026-11-24 (written by the PM; read FIRST) - CireSnave ruled board 498 A
CireSnave 2026-11-24, verbatim: "498: A." You OWN the agent-facing vault tool face (an MCP server over SecretAnt). The boundary is capant's note, read it whole first: `git show dc2c98ebe8bc86f92e1c5306294b9415e55e6d53:docs/THREAT-NOTE-VAULT-TOOL.md` in the capant repo (branch capant-r9; also docs/SCOPING-D2-VAULT-FILE-TOOLS.md). Build ONLY: list secret names (scoped by prefix per role), delivery-placement ledger read, verify-placement yes/no, and delivery to a named file or env file ONLY with a human approval per target path (Windows Hello / with-secret is enough, no typed chat confirmation) and only to allow-listed paths; "run with a secret in its environment" is ask-each-time and its output is never returned unfiltered. NEVER offered: returning a value in any form (get, encoded, hashed prefix, length-revealing partial), put/rotate/import/export/backup/restore, unlock material, Cloudflare delivery. Rules: responses carry names, paths and status only; no value in any result, error or log (SecretValue gets no Display/Serialize); the face keeps its own who-asked-what record and holds no values; delivered files owner-only mode and fail closed if it cannot set it; the host opens the store, never a tool argument. REQUIRED: a test that proves a value can never appear in any response or log (red first). Do NOT take the MCP library choice as settled: rmcp is assessed, not adopted (agent-loop); propose one in a short design note FIRST (one page: crate layout, the library, how approval is called, where the record lives) and send it to pm-ants before building. Branch work now; PRs by the day rule; the capability graph row tool-provider-vault gets your project as provider only when something is built. Never put a secret value in a message or file.


## DONE 2026-11-24 f2e3c7c (pushed): SecretPlacement swap
user-request/with-secret 0.17 (crates.io), KindId::SecretPlacement + Grant::OneUse, subject cap = whole subject 200 (red first), README updated; gates green. The 60 s answer window (WAIT_SECS) stays: present() requires a wait. Still fake-tested only. WAIT 2 (swap) is therefore DONE.

## WAIT (pm-ants TASK 19:4xZ)
Open the vault-tool PR from lane/secretant-d7 at 2026-11-25T00:00Z or later (check: gh pr list -R ThinkersJournal/secretant); pm-ants wakes ~00:12Z. Suspended with lane-restart stop --soft.
