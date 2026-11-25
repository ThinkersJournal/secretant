# Design note: the agent-facing vault tool (proposal, nothing built)

Board 498 A (CireSnave 2026-11-24: "498: A."). Boundary: capant's `THREAT-NOTE-VAULT-TOOL.md`. For pm-ants to accept or change before any code.

## Crate layout
A new workspace member `secretant-mcp` (binary + lib) beside `secretant`; the store crate gains no MCP dependency and no new public API that returns a value. Version moves with secretant (one number per project). The host starts it with the store config (path, unlock, ledger path, allow-list file, role) as **process arguments or a config file the human owns**; no tool argument names a store, an unlock or an allow-list.

## Tools (and only these)
| Tool | Returns |
|---|---|
| `list_names` | names under the caller role's prefix scope |
| `ledger_read` | `{name, target, version}` rows (the existing `Ledger`; no values) |
| `verify_placement` | `in-sync` / `stale` / `missing` per placement (`deliver::verify`) |
| `deliver` | per-placement status only; needs approval per target path, target must be under an allow-listed directory, mode owner-only or fail closed |
| `run_with_secret` | exit status + output passed through `redactant` with the secret registered; ask-each-time. **Proposed for slice 2**, not slice 1 |

No `get`, put, rotate, import, export, backup, restore, unlock, or Cloudflare tool exists in the code, not merely disabled. `SecretValue` stays without `Display`/`Serialize`; the face handles values only inside `deliver::apply`, which never hands one back.

## The library
**Proposed: `rmcp` 3.x via `mcpant`'s `backend` feature** (plain functions served over rmcp; mcpant already pins it, with `limits` for per-call timeout). That adopts rmcp only through mcpant, which is the portfolio's own host layer; the agent-loop assessment ("assessed, not adopted") is why I ask: if you or agent-loop prefer no rmcp, the fallback is a hand-written stdio JSON-RPC loop (`initialize`, `tools/list`, `tools/call`; about 200 lines) with our own tests. Recommend mcpant/rmcp unless agent-loop objects; mcpant is 0.0.3 so I would pin and depend on the crates.io version only.

## How approval is called
`user-request` (crates.io 0.11.1): build a `Request` and call a `Channel::present` (Windows Hello). Its closed `KindId` set has `Secret` (finite grant, "release one secret to one command") but no kind for "place a secret in a file". Two options: (a) reuse `Secret` with subject `NAME -> /abs/path` and a one-hour max grant per path, or (b) ask the consent lane for a new `KindId::SecretPlacement` with `MaxGrant::OneUse`. **Recommend (b)**; slice 1 can use (a) behind a `PlacementApprover` trait so the switch is one file. Denial, timeout or `Unavailable` is a readable result (`denied`), never a retry. No Hello (Linux/macOS) means `deliver` answers `unavailable`; list/ledger/verify still work. The tests use a fake approver; the live prompt is a manual check.

## Where the record lives
The face's own append-only JSON-lines file next to the ledger, owner-only: `{time, role, tool, name, target, outcome}`. Names, paths, outcomes only; written before the tool answers, and a failed write fails the call (closed). It holds no values and is not AuditAnt (a 0.0.0 placeholder); it can move there later.

## The required test (written first, red)
A canary value in the store; drive every tool, every error path (bad name, bad path, denied, store locked, ledger unwritable, panic in the approver) over the real protocol layer; capture every response, every log line (a capturing `log` logger) and the record file; assert the canary and its base64, hex and URL-encoded forms appear in none. Plus a compile-fail-style check that the response types have no `Value`-carrying field, and a test that a path outside the allow-list, a symlink escaping it, and a mode that cannot be set each fail closed with no file written.

## Open for pm-ants
1. rmcp via mcpant, or hand-written stdio.
2. New consent `KindId`, or reuse `Secret` for now.
3. capant's open point: a delivered file inside an allow-listed path is readable by the file tool; the face refuses any allow-list root the host marks as agent-readable (host config `agent_readable_roots`), but the real rule is for capant and the files provider.

— lane: secretant
