kind: Changed
---
The command line names where a bundle passphrase comes from with a small enum instead of two `bool` parameters (TYP-007); behaviour is unchanged and the existing `tests/cli.rs` bundle tests cover both paths. `tools/fresh-eyes-trial.sh` carries an SPDX line (SUP-016).
