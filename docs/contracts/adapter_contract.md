# Adapter Documentation Contract

This contract defines what every Agentic Deep Audit platform adapter must document. It is the
single source of truth for the adapter-doc surface: the per-adapter docs under
`docs/adapters/` and their owning tests conform to it. It is documentation only — the runtime
schema authority lives under `src/agentic_deep_audit/schemas/` (see `output_contract.md`).

## Scope

Agentic Deep Audit exposes one audit engine through several platform adapters. An adapter may
change *how* an audit starts; it must not change *what* a valid audit means. Every adapter
therefore documents the same nine fields, and the set of adapter docs is closed.

## The nine required adapter-doc fields

Every adapter doc under `docs/adapters/` declares the same nine fields, in this order:

1. **adapter id** — the adapter's stable identifier (matches the `launch_surface.adapter`
   value where the adapter writes one).
2. **user entry command** (or runbook entry) — the exact command, or the documented runbook
   entry for docs-first adapters.
3. **required files** — files that must exist in the package root for the adapter to work.
4. **optional files** — files that enhance but are not required for the adapter.
5. **output directory** — where the adapter writes audit artifacts (the portable `audit/`
   tree unless explicitly stated otherwise).
6. **security model** — host config read/write, network, credentials, redaction and no-exec
   posture; see the adapter security matrix in `output_contract.md`.
7. **expected skipped/deferred behavior** — what the adapter emits when an optional tool or
   capability is unavailable (an explicit skipped/deferred artifact or a `TOOL_STATUS.json`
   entry).
8. **validation command** — the command or test that validates the adapter's contract.
9. **ownership of docs/tests** — which test module(s) own the adapter's doc and behavior.

## Closed adapter docs list

The adapter-doc set is closed to these nine entries. A missing doc is a release blocker unless
the adapter is explicitly `deferred` with a recorded reason. Each adapter doc carries the nine
fields above plus its adapter-specific emphasis.

| Adapter | Required doc path | Test owner(s) | Adapter-specific emphasis |
|---|---|---|---|
| CLI | `docs/adapters/cli.md` | `tests/test_adapter_docs_contract.py`, `tests/test_validate_cli.py` | package-root + installed examples; no private-path leakage |
| Python API | `docs/adapters/python-api.md` | `tests/test_adapter_docs_contract.py`, `tests/test_python_api_contract.py` | frozen import surface, semver, deprecation, promotion trigger |
| Codex | `docs/adapters/codex.md` | `tests/test_adapter_docs_contract.py`, `tests/test_adapter_codex.py` | Codex entry point; one adapter, not required for CLI/package |
| Claude Code | `docs/adapters/claude-code.md` | `tests/test_adapter_docs_contract.py`, `tests/test_adapter_claude_code_docs.py` | runbook commands, no-exec warnings, review handoff, expected artifacts |
| MCP | `docs/adapters/mcp.md` | `tests/test_adapter_docs_contract.py`, `tests/test_fixture_mcp_policy.py`, `tests/test_mcp_export.py` | Codex+Claude host scope (SD-3), read-only, collision/redaction |
| GitHub Actions | `docs/adapters/github-actions.md` | `tests/test_adapter_docs_contract.py`, `tests/test_ci_workflows.py` | workflow entry; secrets/permissions/artifact behavior; Windows+Linux matrix |
| Generic CI | `docs/adapters/ci.md` | `tests/test_adapter_docs_contract.py`, `tests/test_adapter_ci_docs.py` | Bash + PowerShell snippets; no private-path tokens |
| Container | `docs/adapters/container.md` | `tests/test_adapter_docs_contract.py`, `tests/test_adapter_container_docs.py` | deferred reason; approval criteria; no host secret mounts |
| Package managers | `docs/adapters/package-managers.md` | `tests/test_adapter_docs_contract.py`, `tests/test_package_install_smoke.py` | pip/pipx install; clean-venv smoke |

## No-overclaim rule

Adapter docs may use only the closed status enum (added to this contract in S-A03). Docs must
not say `supported`, `complete`, `validated`, `verified`, `first-class`, `first-class-docs` or
`first-class-handoff` unless the matching validation command has passed and the evidence is
recorded in the release checklist or review packet. Missing optional tools must never be
presented as successful coverage.

## Status enum

Adapter and OS status labels are closed to exactly these twelve values. Adapter docs may use
no other value, and `first-class`, `first-class-docs` and `first-class-handoff` are distinct
categories that must not be collapsed.

| Status | Meaning |
|---|---|
| `planned` | intended but not yet implemented or documented enough for user reliance |
| `documented-beta` | documented path exists, but public API or user workflow may change |
| `first-class` | executable adapter with entry command, tests, docs and release evidence |
| `first-class-docs` | docs-first adapter with tested runbook but no host-native executable wrapper |
| `first-class-handoff` | output-only or read-only handoff with tested artifact access |
| `optional` | useful but not required for a valid audit |
| `deferred` | intentionally out of current implementation tranche |
| `research-only` | prior art or exploratory adapter, not a product claim |
| `staged-alpha` | present only behind explicit operator or developer gate |
| `staged-beta` | present and tested in limited CI/release evidence |
| `verified` | validation evidence is recorded for the stated OS/adapter |
| `unverified` | not validated yet and must not be marketed as supported |

Demotion of any status is recorded with evidence in `RELEASE_CHECKLIST.md` (`## Demotion Evidence`).

## Security matrix

Every adapter doc carries a `## Security` matrix declaring the same seven security columns.
This contract defines those columns as the source of the standard; each adapter doc fills one
value row, grounded in that adapter's `security model` field, and the canonical engine-wide
matrix is also summarized in `output_contract.md`. The seven columns are:

| Column | What it records |
|---|---|
| `target execution` | whether the adapter runs target-repo code (the engine is a static, read-only audit and runs none). |
| `network default` | the default network posture (default-deny unless a validated policy or an install step is explicitly noted). |
| `host config access` | whether the adapter reads host configuration (none, except the agent/MCP adapters reading host MCP config as read-only metadata for collision detection). |
| `credentials` | whether the adapter reads credentials (none read). |
| `redaction verification` | which tests verify redaction of the adapter's artifacts (the provenance/MCP redaction tests). |
| `no-exec enforcement` | how command execution is blocked (the PreToolUse hook blocks command execution; the engine performs no target-repo execution). |
| `write permissions` | where the adapter is allowed to write (confined to the generated `audit/` output tree, and `.audit-tmp/` for build/install smoke). |

A doc that omits any of these seven columns is a release blocker (enforced by
`tests/test_adapter_docs_contract.py`).
