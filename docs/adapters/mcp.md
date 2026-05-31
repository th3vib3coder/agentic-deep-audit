# MCP Adapter

Status: `documented-beta` (target `first-class-handoff`, pending recorded release evidence). The MCP
adapter is a read-only handoff: it exposes a generated `audit/` tree to MCP host agents and writes
nothing. It declares the nine required adapter-doc fields from `docs/contracts/adapter_contract.md`.

## adapter id

`mcp`

## user entry command

`python -m agentic_deep_audit.mcp_readonly_server --help` (the server advertises its read-only
nature). Point an MCP host at the read-only server to access an existing `audit/` tree; it exposes
read tools (artifact read, corpus query, graph neighbors) only.

## required files

- `src/agentic_deep_audit/mcp_readonly_server.py` — the read-only server.
- `src/agentic_deep_audit/mcp_collision_check.py` — host-config collision/redaction discovery.

## optional files

- a runbook extension documenting host-specific setup.

## output directory

The existing `audit/` tree, accessed **read-only** (the server creates and modifies nothing).

## security model

- target-repo code execution: none;
- network: none unless the host provides transport;
- host config access: read-only metadata for collision detection (Codex + Claude Code);
- credentials: no credential read beyond redacted metadata;
- redaction verification: MCP collision/secret fixtures;
- write permissions: none (read-only server).

## Security

The seven adapter security columns for `mcp`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (read-only handoff server; never executes target-repo code) | denied (default-deny; no network unless the host provides transport) | reads host MCP config as read-only metadata for collision detection only | none read beyond redacted metadata | covered by the provenance/MCP redaction tests and the collision/secret fixtures | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | none (read-only server writes nothing) |

## expected skipped/deferred behavior

Discovered hosts other than Codex and Claude Code are `unverified` (see the host table); collision
discovery runs generically but those hosts are not per-host validation-tested. A missing host config
defers without writing any generated config.

## validation command

`python -m pytest tests/test_fixture_mcp_policy.py tests/test_mcp_export.py -q`

## ownership of docs/tests

`tests/test_fixture_mcp_policy.py` and `tests/test_mcp_export.py`.

## Host scope (SD-3)

Collision/redaction discovery already covers many host configs. For this tranche only **Codex** and
**Claude Code** are `verified` (per-host tested by the host-coverage, read-only and redaction tests);
every other discovered host is `unverified` — discovery runs generically but those hosts are not
per-host validation-tested, and they are not removed (removing working capability would be wasteful).
No `unverified` host may be marketed as supported. Rationale: the operator verifies Codex + Claude
Code only this tranche (SD-3). Silence about host breadth was the v1 hidden-coupling defect and must
not recur.

| Host | Config path | Status |
|---|---|---|
| Codex | `~/.codex/mcp.json` | `verified` |
| Claude Code | `~/.claude/mcp.json` | `verified` |
| Cursor | `~/.cursor/mcp.json` | `unverified` |
| Continue | `~/.continue/mcp.json` | `unverified` |
| Goose | `~/.goose/mcp.json` | `unverified` |
| Zed | `~/.zed/mcp.json` | `unverified` |
| Windsurf | `~/.windsurf/mcp.json` | `unverified` |
| Antigravity | `~/.antigravity/mcp.json` | `unverified` |
| VS Code | `~/.vscode/mcp.json`, `~/AppData/Roaming/Code/User/mcp.json` | `unverified` |
| Claude Desktop | `~/AppData/Roaming/Claude/claude_desktop_config.json` | `unverified` |
