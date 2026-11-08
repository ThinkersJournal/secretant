# SecretAnt lane HANDOFF

Written 2026-11-08 by the PM. Current state only; history is in git.

## Why this lane exists (CireSnave, 2026-11-07)
"Humboldt's installer is waiting on configurant. Configurant's secrets are waiting on secretant. We have no secretant lane."
Chain: Humboldt installer (docs/INSTALLER-DESIGN.md) -> ConfigurAnt (rows 4 and 25: a `SecretSource` adapter crate for SecretAnt)
-> SecretAnt (a 0.0.0 placeholder on crates.io; design merged in #1, 452 lines, `docs/DESIGN.md`).

## State
- Repo ThinkersJournal/secretant, main at 0.0.1 (design note only), CI and licences in place. No code. Your worktree: C:\Projects\secretant-wt-lane
  on branch lane/secretant. The primary checkout C:\Projects\secretant stays on main; never switch it.
- Requirements are CireSnave's verbatim words in DESIGN.md section 1 and 2 (every install sets up SecretAnt for the installer; a school's secrets
  never live in a service we run). Do not weaken them.

## First task (do not wait for a [TASK])
1. Read `docs/DESIGN.md` whole, and ConfigurAnt's `docs/SECRET-SOURCES.md` on `origin/main` of ThinkersJournal/configurant (what its adapter needs).
2. Write the build order as ROADMAP.md rows: the smallest v1 that lets ConfigurAnt publish its adapter and lets the Humboldt installer keep a
   school's secrets in one place the school controls. Name what is NOT in v1. Each row: deliverable, test, what it unblocks, who is waiting.
3. List every open decision in DESIGN.md (D1, D2, ... including D4 on the Humboldt Worker) with your recommendation, in full plain sentences, and
   send the PM an [ASK] with only the ones that block row 1. The PM puts them on CireSnave's board; do not ask him yourself.
4. Start row 1 (library core: `SecretValue` with no Debug/Display/Clone/Serialize and wiped on drop, store trait, file format, put/get/list)
   red-first, one PR per slice, fragment-free repo: put the next version in the PR, the PM allocates at the gate.

## Rules that bite here
- Secrets: a test or log must never print a value; settle any dispute by hash or count, never displayed text.
- Crates.io versions only for cross-repo dependencies; claim nothing new (the name `secretant` is claimed).
- Patent sweep: `PATENT-SWEEP.md` exists; add rows for any new technique before it ships.
- Cost: Sonnet only; short messages; headers per MESSAGE-FORMATS.md.
- Open an issue or PR as the lane account (ciresnave-bot). Never `gh auth switch`.

## Waiting on
Nothing. The PM gates and publishes; ConfigurAnt (rows 4 and 25) and Humboldt wait for you, so send [READY] after each slice.
