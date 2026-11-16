kind: architecture declared for the ARC checks
---
`.coderipper.toml` declares secretant's architecture (module groups foundation, services, cloudflare, place, cli in four layers) so the ARC checks run instead of reporting "not run"; the code already obeys it (ARC-001 judged 6 edges, ARC-002 found 0 cycles, ARC-005 reported 0). The ARC-009 surface finding (growth since the 0.0.2 skeleton) and the five MOD-008 pass-through Info findings are waived with their reasons: the installer step contract's four calls, and the platform facade. No code changes.
