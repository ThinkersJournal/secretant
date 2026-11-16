kind: Changed
---
ROADMAP.md status now matches the forge (rows 1 to 8 merged, 9 to 11 blocked, with the reason). New test `a_truncated_backup_or_bundle_fails_loudly_and_changes_nothing` in tests/cli.rs: a backup or export bundle cut to 0, 1, half and all-but-one bytes fails `restore-test`, `restore` and `import --apply` with exit 1, prints no canary and leaves the store byte-identical (it passed on first run, so it guards the behaviour rather than fixing a bug).
