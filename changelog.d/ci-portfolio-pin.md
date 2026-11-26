kind: CI: portfolio workflow pinned to coderipper 0.48.1
---
The advisory `portfolio` job in `.github/workflows/ci.yml` now calls `ciresnave/coderipper/.github/workflows/portfolio.yml` at `467fd259d6d062cba4c5683d310f1a6f2b66e763` (coderipper 0.48.1, was 0.47.13). No rule is silenced and nothing else changes; the job stays advisory. Verified by reading the check at the pin on the PR.
