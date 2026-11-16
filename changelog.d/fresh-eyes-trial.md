kind: Added
---
`tools/fresh-eyes-trial.sh`: sets up the fresh-eyes trial (EXPECTATIONS 6.24). It builds the crate as `cargo package` ships it, makes a fresh project with only the README and rustdoc, prints the brief and times the run; `finish` runs the result. First run (0.0.36, blind Sonnet agent): PASS, one stumble, reported separately.
