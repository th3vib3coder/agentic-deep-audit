# Release Checklist

Status: package ready for external review; not released.

Sources: `piano_doc/implementazione/029_seq_release_checklist_and_docs.md`, `piano_doc/018_output_matrix.md`, `piano_doc/010_metriche_validazione.md`.

Inputs: accepted HAT 2 sequences, validation engine, smoke tests, review packet.

Outputs: release commands, pass conditions and caveats for package review.

Validation: this checklist cannot claim release readiness unless every command below passes on the release candidate.

## Required Commands

Run from repository root.

| Gate | Command | Expected pass condition |
|---|---|---|
| Schema and unit validation | `PYTHONPATH=src pytest tests -q` | all package tests pass; current acceptance baseline is 334 collected tests |
| Package metadata and skill routing | `PYTHONPATH=src pytest tests/test_release_packaging.py -q` | `.codex-plugin/plugin.json`, `pyproject.toml`, skill references and console alias are valid |
| Smoke audits | `PYTHONPATH=src python tests/run_smoke_tests.py --report audit/SMOKE_TEST_REPORT.md` | at least three fixture audits pass and list required artifacts |
| Policy tests | `PYTHONPATH=src pytest tests/test_pre_tool_policy.py tests/test_network_policy.py tests/test_fixture_mcp_policy.py -q` | no-exec, network precedence, MCP collision and redaction gates pass |
| Wiki and corpus checks | `PYTHONPATH=src pytest tests/test_wiki_pages.py tests/test_corpus_retrieval.py -q` | wiki links/frontmatter and corpus FTS/hash smoke checks pass |
| Gate hook | `PYTHONPATH=src pytest tests/check_gate_paths.py -q` | HAT 2 path gate fails closed outside `operator_go` and allows current implementation scope |
| Static compile | `PYTHONPATH=src python -m compileall -q -x "tests[\\/]fixtures" src tests` | package and tests compile without generating cache under fixture repositories |
| Git whitespace | `git diff --check` | no whitespace errors |

PowerShell form uses `$env:PYTHONPATH = "src"` before the command.

Planning provenance checkers are covered by `tests/test_seq_atomicity.py` and `tests/test_plan_traceability.py`. Run `tests/check_seq_atomicity.py` and `tests/check_plan_traceability.py` directly only in a planning workspace that includes `piano_doc/`.

## Release Scope

- This is an audit engine package with CLI, Codex, MCP and package adapters for local use and external review.
- Release is blocked if `VALIDATION_REPORT.md` contains any blocker.
- `ADVERSARIAL_REVIEW_PACKET.md` is a handoff artifact for an external reviewer; it is not a self-acceptance.
- Optional adapters remain deferred unless their `adapter_decision.json` says `promote` and passes the adapter schema.

## Non-Claims

- No legal advice.
- No vulnerability-free or production-safe certification.
- No claim that optional external tools are accepted dependencies unless promoted by the Adapter Promotion Gate.
- No runtime execution of target repository commands in default `source-audit` mode.
