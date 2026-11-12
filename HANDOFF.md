# SecretAnt lane HANDOFF

Rewritten 2026-11-12T01:06Z by the lane. Current state only; history is in git.

## State
- Repo ThinkersJournal/secretant. Worktrees: C:\Projects\secretant-wt-lane (lane/secretant = PR #4), C:\Projects\secretant-wt-row3 (lane/row3-read = PR #5, base lane/secretant). Primary checkout stays on main.
- Done and in PRs: row 2 key wraps (#4, 0.0.4 allocated, red only on CodeRipper reachability + SEC-002, both routed by the PM to the coderipper lane; do NOT reword or suppress); row 3 SecretReader (#5, 0.0.5 allocated, stacked on #4, no-cache and timeout mutations done).
- Row 4 (CLI) is next after the stack lands. Requirements in DESIGN.md sections 1-2 are CireSnave's words.

## Tasks held
1. After #4 squash-merges: retarget #5 to main (`git rebase --onto origin/main <old #4 tip> lane/row3-read`), push, [READY] with the rebased head. Old #4 tip is the head of lane/secretant at merge time.
2. After #4 and #5 land: ONE PR adopting fragment+stamp (PM task 2026-11-12). Copy from C:\Projects\tools\fragment-stamp-kit\: stamp-version.py and check-fragment.py to tools/, changelog-fragment.yml to .github/workflows/ (pin the same checkout SHA), README-changelog.d.md to changelog.d/README.md. Test: throwaway changelog.d/x.md, `python tools/stamp-version.py 99.99.99 --root . --dry-run` must list Cargo.toml, Cargo.lock, CHANGELOG.md; delete the throwaway. Copy the kit FRESH at adoption (PM notice 2026-11-12: stamp-version.py was fixed for workspace-inherited versions, `{ version, path }` dep lines, optional tools/stamp-current.txt, non-UTF-8 CHANGELOGs); also run a REAL stamp on a scratch copy of the repo and grep every Cargo.toml for the OLD version: nothing may remain. Pins `=X.Y.Z` go in tools/stamp-extra.txt. The adoption PR bumps its own version once; later PRs carry one changelog.d fragment and no version edit. [READY] when done; [ASK] if the dry run fails.

## Waits
WAIT: pr4-merged | check: gh pr view 4 --json state,mergedAt | wake: 2026-11-12T03:06:00Z
WAIT: pr5-merged | check: gh pr view 5 --json state,mergedAt | wake: 2026-11-12T03:06:00Z

## Rules that bite
Never print a secret value in tests/logs. Crates.io deps only. Add docs/PATENT-SWEEP.md rows for new techniques. Sonnet only. Never `gh auth switch`. Sign PR text `- lane: secretant`. Write Windows files with the Write tool or a file, not a bash heredoc holding quotes.
