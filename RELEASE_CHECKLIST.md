# Release Checklist

Status: package ready for external review; not released.

Sources: internal release-planning artifacts (retained in the private planning workspace).

Inputs: accepted implementation sequences, validation engine, smoke tests, review packet.

Outputs: release commands, pass conditions and caveats for package review.

Validation: this checklist cannot claim release readiness unless every command below passes on the release candidate.

## Required Commands

Run from repository root.

| Gate | Command | Expected pass condition |
|---|---|---|
| Schema and unit validation | `PYTHONPATH=src pytest tests -q` | all package tests pass; current acceptance baseline is 362 collected tests |
| Package metadata and skill routing | `PYTHONPATH=src pytest tests/test_release_packaging.py -q` | `.codex-plugin/plugin.json`, `pyproject.toml`, skill references and console alias are valid |
| Smoke audits | `PYTHONPATH=src python tests/run_smoke_tests.py --report audit/SMOKE_TEST_REPORT.md` | at least three fixture audits pass and list required artifacts |
| Policy tests | `PYTHONPATH=src pytest tests/test_pre_tool_policy.py tests/test_network_policy.py tests/test_fixture_mcp_policy.py -q` | no-exec, network precedence, MCP collision and redaction gates pass |
| Wiki and corpus checks | `PYTHONPATH=src pytest tests/test_wiki_pages.py tests/test_corpus_retrieval.py -q` | wiki links/frontmatter and corpus FTS/hash smoke checks pass |
| Gate hook | `PYTHONPATH=src pytest tests/check_gate_paths.py -q` | the path gate fails closed outside `operator_go` and allows the current implementation scope |
| Static compile | `PYTHONPATH=src python -m compileall -q -x "tests[\\/]fixtures" src tests` | package and tests compile without generating cache under fixture repositories |
| Git whitespace | `git diff --check` | no whitespace errors |

PowerShell form uses `$env:PYTHONPATH = "src"` before the command.

Planning-provenance checkers (`tests/check_seq_atomicity.py`, `tests/check_plan_traceability.py`, with `tests/test_seq_atomicity.py` and `tests/test_plan_traceability.py`) run only in the private planning workspace and are excluded from the shipped package.

## Public-Root Scan Commands

The authoritative public-root leak gate (forbidden tree entries + content tokens) is the Python test:

```bash
PYTHONPATH=src pytest tests/test_public_root_export.py -q
```

The cross-shell `rg` human-aid scans, with the documented allowlist/exclusions, live verbatim in
`docs/contracts/release_gates_bash.md` and `docs/contracts/release_gates_powershell.md`. Planning-only
checkers and the private review ledgers are excluded from the public export by the sync script; the
`EXPORT_EXCLUDED` set in `tests/test_public_root_export.py` mirrors that exclusion (scan/sync parity).

## OS Evidence

Per-OS release evidence (SD-4). Status stays `unverified` until the cross-OS CI matrix is green on
the recorded commit SHA; macOS is `deferred` with no active job in this tranche.

| Runner | Shell | Python version | Command output | Commit SHA | Status |
|---|---|---|---|---|---|
| `ubuntu-latest` | bash | 3.10 / 3.11 / 3.12 | pending first green matrix run | pending | `unverified` |
| `windows-latest` | bash (Git-Bash via `defaults.run.shell`) | 3.10 / 3.11 / 3.12 | pending first green matrix run | pending | `unverified` |
| `macos-latest` | — | — | — | — | `deferred` (SD-4: no macos-latest CI job in this tranche) |

## Export Record

| Field | Value |
|---|---|
| Public target branch | `codex/agentic-deep-audit-implementation` |
| Collected tests | 599 collected — 591 passed, 8 skipped (monorepo package suite) |
| Sync command | `tools/sync-agentic-plugin-to-publish-root.ps1 -RunTests -Commit -Push` |
| Source / publish SHAs | recorded in the private review ledger after each push |

The public package is exported only through the sync script (path/blob/name safety plus the
in-isolation test suite); the private planning workspace, the private review ledgers, and the
planning-only checkers are excluded from the export.

## Release Scope

- This is an audit engine package with CLI, Codex, MCP and package adapters for local use and external review.
- Release is blocked if `VALIDATION_REPORT.md` contains any blocker.
- `ADVERSARIAL_REVIEW_PACKET.md` is a handoff artifact for an external reviewer; it is not a self-acceptance.
- Optional adapters remain deferred unless their `adapter_decision.json` says `promote` and passes the adapter schema.

## Demotion Evidence

If a promotion-target adapter is demoted (its closed-enum status lowered), record the evidence
here — one sub-table row per demotion event. Cells stay blank until an actual demotion occurs.
The status values used must come from the closed status enum in `docs/contracts/adapter_contract.md`.

### CLI

| old status | new status | evidence | next review gate |
|---|---|---|---|
|  |  |  |  |

### Codex

| old status | new status | evidence | next review gate |
|---|---|---|---|
|  |  |  |  |

### Claude Code

| old status | new status | evidence | next review gate |
|---|---|---|---|
|  |  |  |  |

### MCP

| old status | new status | evidence | next review gate |
|---|---|---|---|
|  |  |  |  |

## Non-Claims

- No legal advice.
- No vulnerability-free or production-safe certification.
- No claim that optional external tools are accepted dependencies unless promoted by the Adapter Promotion Gate.
- No runtime execution of target repository commands in default `source-audit` mode.
