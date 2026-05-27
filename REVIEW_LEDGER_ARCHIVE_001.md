# Agentic Deep Audit Review Ledger Archive 001

Status: archived HAT 2 review rows through SEQ-014.

Sources: REVIEW_LEDGER.md before SEQ-018 ledger update.

Inputs: accepted sequence review rows SEQ-002 through SEQ-014 plus historical SEQ-001 ordering.

Outputs: immutable archive of older per-sequence HAT rows.

Validation: active REVIEW_LEDGER.md points here; archive preserves reviewer names, commands, blockers, remediation and status.

## Archived Sections

## SEQ-014 - Public Surface Extraction

Author: Codex.
Reviewer: Jason.
Gate: `operator_go`.
Commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`
- `python -m py_compile plugins/agentic-deep-audit/src/agentic_deep_audit/audit_surface.py plugins/agentic-deep-audit/src/agentic_deep_audit/audit_validate.py plugins/agentic-deep-audit/src/agentic_deep_audit/cli.py`

Blockers:

- REDIRECT-SEQ014-001/P1: dotenv files were recognized as config targets, but `KEY=value` env names were not extracted.
- Process drift: prior SEQ-013 ledger closure named a non-existent next sequence file.

Remediation:

- Added `audit_surface.py` with conservative API route, CLI, MCP and config/env surface extraction.
- Added surface JSON schemas for API, CLI, MCP and config outputs.
- Added validator checks for evidence ids, source path, status, sanitizer decision, no executable target scripts, no host MCP import and no env value reads.
- Added fixture coverage for REST, GraphQL, gRPC, WebSocket, package scripts, Node bins, Cargo bins, Go commands, target MCP config, Markdown env references and dotenv env names.
- Corrected the next sequence reference to `014_seq_surface_extraction.md`.

Review verdict: ACCEPT after REDIRECT-SEQ014-001 remediation.
Accepted commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v` -> 124 passed.
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD` -> OK.
- `git diff --check` -> OK.
- `py_compile` -> OK.

Reviewer notes:

- Dotenv names are recorded; values are not emitted.
- Target MCP configs are audit data only and are never imported into host config.

Status: OK.

## SEQ-013 - Module, Symbol And Call Graph

Author: Codex.
Reviewer: Gemini CLI.
Gate: `operator_go`.
Commands:

- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_centrality.py plugins/agentic-deep-audit/tests/test_graph_extraction.py plugins/agentic-deep-audit/tests/test_cli_config.py -v`
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ013-001/P1: `MODULE_GRAPH` schema accepted edges without `evidence_ids`.
- REDIRECT-SEQ013-002/P1: centrality override was only config-driven; the plan required `--graph-centrality` and exact tests in `tests/test_centrality.py`.

Remediation:

- Added `audit_graph.py` with Python AST extraction, conservative JS/TS extraction, minimal Go/Rust/Java/Kotlin/Generic parsers, module/symbol/call graph emission and deterministic architecture baseline.
- Added `MODULE_GRAPH.json`, `SYMBOL_INDEX.json`, `CALL_GRAPH.json`/`CALL_GRAPH_SKIPPED.md` validation.
- Required `evidence_ids` on module graph edges at schema level and added a negative schema test.
- Added CLI `--graph-centrality`, `RUN_CONFIG.json`/`override_source` propagation and `TOOL_STATUS.json` override logging.
- Split centrality tests into `tests/test_centrality.py::test_default_algorithm` and `tests/test_centrality.py::test_override_logging`.

Review verdict: ACCEPT after REDIRECT-SEQ013-001 and REDIRECT-SEQ013-002 remediation.
Accepted commands:

- targeted centrality/graph/cli tests -> 16 passed.
- full test suite -> 117 passed.
- gate check paths -> OK.
- `git diff --check` -> OK.

Reviewer notes:

- Language parsers are conservative and mark partial coverage instead of guessing unsupported semantics.
- Dynamic JS/TS require is skipped/partial, not converted into speculative edges.

Status: OK.

## SEQ-012 - Adapter Framework And Promotion Gate

Author: Codex.
Reviewer: Aristotle.
Gate: `operator_go`.
Commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ012-001/P1: `adapter_decision.json` could promote the wrong adapter when the file path requested `madge` but payload `adapter_id` declared `graphify`.

Remediation:

- Added adapter base contract with `detect`, `run`, `parse` and `status`.
- Added promotion-gate loader that blocks `source-claim` and `industry-known` adapters unless `adapter_decision.json` is valid, matches the requested adapter id and has `decision: promote`.
- Added machine-checkable adapter decision schema plus development-time `ADAPTER_EVALUATION.md`.
- Extended `TOOL_STATUS.json` records with OS, capability, availability, degradation reason and provenance class.
- Added raw output retention under `audit/raw/<tool>/`, secret-like output redaction, timeout, cwd containment, output containment and network hook tests.

Review verdict: ACCEPT after REDIRECT-SEQ012-001 remediation.
Accepted commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v` -> 110 passed.
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD` -> OK.
- `git diff --check` -> OK.

Reviewer notes:

- Optional prior-art adapters remain non-operational until promoted.
- Adapter-specific implementations are intentionally deferred to later sequences behind this gate.

Status: OK.

## SEQ-011 - Manifest, Build, Test And CI Map

Author: Codex.
Reviewer: Planck.
Gate: `operator_go`.
Commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_manifest_parsing.py -v`
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ011-001/P1: malformed manifest syntax crashed `run_manifest()` instead of producing skipped records.
- REDIRECT-SEQ011-001/P1: GitHub Actions block scalar `run: |` was recorded as literal `|`.
- REDIRECT-SEQ011-002/P1: shape-malformed `package.json` crashed with `AttributeError`.

Remediation:

- Added fail-soft manifest parse records with `skipped: true`, `evidence_ids` and `skip_reason`.
- Added CI command extraction for inline `run:` and block scalar `run: |` / `run: >`.
- Added phase 2 validation for manifest/CI evidence ids and observed-only no-exec command labels.
- Ensured target repo manifest commands are classified as `target_repo_manifest_no_exec` before broader denylist rules.

Review verdict: ACCEPT after REDIRECT-SEQ011-001 and REDIRECT-SEQ011-002 remediation.
Accepted commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_manifest_parsing.py -v` -> 8 passed.
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v` -> 98 passed.
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD` -> OK.
- `git diff --check` -> OK.

Reviewer notes:

- Parser coverage is conservative and no-exec by design.
- Safety guarantee is anchored in JSON records and the policy engine; Markdown map is generated from those records.

Status: OK.

## SEQ-010 - Evidence Index And Byte Ranges

Author: Codex.
Reviewer: Sartre.
Gate: `operator_go`.
Commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_evidence_byte_ranges.py -v`
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ010-001/P1: `file_line` and binary-safe evidence could pass validation without byte ranges.
- REDIRECT-SEQ010-001/P1: evidence drift validation was not anchored strongly enough to `PROVENANCE.json` path and commit identity.
- REDIRECT-SEQ010-001/P1: downstream JSON artifacts with orphan `evidence_ids` were not validated against `EVIDENCE_INDEX.json`.
- REDIRECT-SEQ010-002/P1: blank/non-string downstream `evidence_ids` could pass reachability validation.
- REDIRECT-SEQ010-003/P1: Windows root-relative and drive-relative evidence paths could bypass path safety.

Remediation:

- Added `audit_evidence.py` with stable `ev-000001` allocation, text metadata, byte-range hashing, binary-safe evidence and claim resolver helpers.
- Required byte ranges for byte-addressable and binary-safe evidence in schema and validation.
- Synced evidence repo identity from provenance and validated path/commit drift.
- Added cross-artifact JSON `evidence_ids` reachability validation, including invalid blank and non-string ids.
- Hardened evidence path safety with POSIX/Windows root, drive, separator, colon, NUL, `..` and resolved containment checks.

Review verdict: ACCEPT after REDIRECT-SEQ010-001, REDIRECT-SEQ010-002 and REDIRECT-SEQ010-003 remediation.
Accepted commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_evidence_byte_ranges.py -v` -> 18 passed.
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v` -> 90 passed.
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD` -> OK.
- `git diff --check` -> OK.

Reviewer notes:

- Residual risk: cross-artifact reachability currently covers JSON `evidence_ids`; Markdown links are deferred to later wiki/report validators.
- Residual risk: current evidence is file-level whole-range; symbol/snippet ranges are owned by later graph/surface/synthesis sequences.

Status: OK.

## SEQ-009 - Provenance Git And GitHub Metadata

Author: Codex.
Reviewer: Mill.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py plugins/agentic-deep-audit/tests/test_policy_security.py plugins/agentic-deep-audit/tests/test_bootstrap_phase0.py plugins/agentic-deep-audit/tests/test_inventory_file_index.py plugins/agentic-deep-audit/tests/test_provenance_git_github.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ009-001/P1: `PROVENANCE.json` could leak a configured `repo.github` token because raw `run_config["repo"]` was copied into output.
- REDIRECT-SEQ009-001/P1: git detection skipped repositories when `repo.path` pointed at a subdirectory and `.git` lived in a parent root.
- REDIRECT-SEQ009-001/P1: deny-all network policy snapshot produced GitHub metadata `deferred` instead of `skipped`.
- REDIRECT-SEQ009-002/P1: missing `git` executable raised `FileNotFoundError` and prevented always-emitted `PROVENANCE.json`.

Remediation:

- Sanitize the emitted `repo` object and validate the full `PROVENANCE.json` tree for secret-like strings.
- Use allowlisted `git rev-parse --show-toplevel` as the primary git detection path; fallback no-git only when the command fails.
- Evaluate the network policy snapshot with `decide_network("api.github.com")`; blocked GitHub metadata is now `skipped`.
- Add regression tests for configured GitHub token redaction, subdirectory git detection and deny-all network policy.
- Convert missing `git` executable into deterministic provenance fallback with `limitations: ["git executable not found"]` and command skipped reason.

Review verdict: ACCEPT after REDIRECT-SEQ009-001 and REDIRECT-SEQ009-002 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/test_provenance_git_github.py -v`
- `python -m pytest plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Reviewer notes:

- Configured GitHub tokens are redacted from `PROVENANCE.json` and `TOOL_STATUS.json`.
- Git repos are detected from subdirectory `repo.path` via `git rev-parse --show-toplevel`.
- Deny-all network policy records `github_metadata` as `skipped`.
- Missing `git` executable emits deterministic fallback and does not block `PROVENANCE.json`.

Status: OK.

## SEQ-008 - Inventory And File Index

Author: Codex.
Reviewer: Carson.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py plugins/agentic-deep-audit/tests/test_policy_security.py plugins/agentic-deep-audit/tests/test_bootstrap_phase0.py plugins/agentic-deep-audit/tests/test_inventory_file_index.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers:

- REDIRECT-SEQ008-001/P1: absolute nested output dir such as `repo/reports/audit` was indexed because the walker excluded only the output basename.
- REDIRECT-SEQ008-001/P1: `inventory --dry-run` planned `PROVENANCE.json` instead of `EVIDENCE_INDEX.json`.
- REDIRECT-SEQ008-002/P1: broad pytest collection entered `tests/fixtures/python_basic/tests/test_app.py` and failed on fixture-only import.

Remediation:

- Exclude the resolved output dir relative to the repo path, covering nested absolute output paths.
- Update CLI planned artifacts for `inventory` to include `EVIDENCE_INDEX.json` and not `PROVENANCE.json`.
- Add regression tests for absolute nested output exclusion and dry-run artifact planning.
- Configure pytest to ignore `tests/fixtures` during broad suite collection while keeping fixture files available to inventory tests.

Review verdict: ACCEPT after REDIRECT-SEQ008-001 and REDIRECT-SEQ008-002 remediation.
Accepted commands:

- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests -v`
- `python -m pytest -p no:cacheprovider plugins/agentic-deep-audit/tests/test_inventory_file_index.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Reviewer notes:

- Absolute nested output dir under repo is excluded.
- `inventory --dry-run` plans `EVIDENCE_INDEX.json`, not `PROVENANCE.json`.
- Broad pytest no longer collects fixture tests.
- No target repo execution patterns found in SEQ-008 runtime files.

Status: OK.

## SEQ-007 - Bootstrap Run State And Tool Status

Author: Codex.
Reviewer: Gibbs.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py plugins/agentic-deep-audit/tests/test_policy_security.py plugins/agentic-deep-audit/tests/test_bootstrap_phase0.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Blockers: none.

Review verdict: ACCEPT.
Accepted commands:

- `pytest plugins/agentic-deep-audit/tests/test_bootstrap_phase0.py -v`
- `pytest plugins/agentic-deep-audit/tests -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Reviewer notes:

- Phase 0 creates `audit/` through the skill script and rejects outside-root output.
- Config and network policy snapshots are hashed and recorded.
- Missing network policy is represented as `skipped` with network-adapter blocking reason.
- `TOOL_STATUS.json`, `PROGRESS.md`, `BLOCKED_COMMANDS_ATTEMPTS.json` and phase 0 validation match the plan.
- No target repo command execution was found; introduced subprocess use is limited to core tool version probes.

Status: OK.

## SEQ-001 - Gate Hook And Repo Discipline

Author: Codex.
Reviewer: Copernicus.
Gate: `operator_go`.
Commands:

- `python -m pytest tests/check_gate_paths.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ001-001/P1: commands were not reproducible without explicit package path.
- REDIRECT-SEQ001-001/P1: `check-paths --base HEAD` initially included uncommitted HAT 1 plan rewrite.
- REDIRECT-SEQ001-001/P2: test did not contain its own expected `GATE_POLICY` table.

Remediation:

- Added `tests/conftest.py` and documented explicit `PYTHONPATH` for subprocess command execution.
- Committed the accepted HAT 1 documentation baseline before final gate verification.
- Added expected module-level `GATE_POLICY` in `tests/check_gate_paths.py` and assert runtime parity.

Review verdict: ACCEPT after REDIRECT-SEQ001-001 remediation.
Accepted commands:

- `python -m pytest tests/check_gate_paths.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Status: OK.

## SEQ-006 - Policy No-Exec Network And Sanitizer

Author: Codex.
Reviewer: Mendel.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py plugins/agentic-deep-audit/tests/test_policy_security.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ006-001/P1: command allowlist used prefix matching and falsely allowed `git statusx`, `python -m agentic_deep_audit_bad`, and `python -m agentic_deep_audit.evil`.
- REDIRECT-SEQ006-001/P1: `send_source_code: false` missed common JS, Go and SQL snippets.
- REDIRECT-SEQ006-001/P2: target repo manifest test used `npm install`, which was blocked by `blocked_always` rather than the origin-specific no-exec rule.
- REDIRECT-SEQ006-001/P2: MCP redaction fixture did not cover high-entropy strings.

Remediation:

- Replaced command prefix matching with token-prefix matching against explicit allowlist patterns.
- Expanded source payload classification for JS/TS declarations, Go `package main` and SQL `SELECT ... FROM`.
- Added regression tests for allowlisted command from `target_repo_manifest`, false allow command variants and high-entropy MCP redaction.

Review verdict: ACCEPT after REDIRECT-SEQ006-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/test_policy_security.py -v`
- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py plugins/agentic-deep-audit/tests/test_policy_security.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.

## SEQ-005B - Schema Registry Group B

Author: Codex.
Reviewer: Laplace.
Gate: `operator_go`.
Scope: `005_seq_schema_registry_core_models.md` Group B only, steps 005.8-005.9.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ005B-001/P1: structurally corrupt but valid JSON schema errors included schema name but not schema path.

Remediation:

- Wrapped `_validate_schema_shape` errors with schema name and path in `load_schema_registry`.
- Added negative test for structurally corrupt schema file with missing `title`.

Review verdict: ACCEPT after REDIRECT-SEQ005B-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py plugins/agentic-deep-audit/tests/test_models.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.

## SEQ-005A - Schema Registry Group A

Author: Codex.
Reviewer: Kierkegaard.
Gate: `operator_go`.
Scope: `005_seq_schema_registry_core_models.md` Group A only, steps 005.1-005.7a.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ005A-001/P1: `x-kind-required` and `x-status-required` were test-only custom keywords ignored by real JSON Schema validators.
- REDIRECT-SEQ005A-001/P2: `blocked_commands.schema.json` required allowlist keys but did not type their values.
- REDIRECT-SEQ005A-001/P2: skipped `PROJECT_TELEMETRY.json` records allowed empty `limitations`.

Remediation:

- Replaced custom schema keywords with JSON Schema 2020-12 `if`/`then` conditions.
- Switched Group A schema tests to `jsonschema.Draft202012Validator`.
- Typed blocked-command allowlist items and added negative fixture.
- Added skipped telemetry `limitations` non-empty rule and negative fixture.
- Removed obsolete custom test-only schema helper.

Review verdict: ACCEPT after REDIRECT-SEQ005A-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py plugins/agentic-deep-audit/tests/test_schema_registry_group_a.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.

## SEQ-004 - CLI, Config And Run Model

Author: Codex.
Reviewer: Linnaeus.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ004-001/P1: optional CLI args `--renderer`, `--graphify`, `--network-policy`, `--graph-source` were accepted but not written into `RUN_CONFIG.json`.
- REDIRECT-SEQ004-001/P2: missing config path raised a Python traceback instead of a clear CLI error.

Remediation:

- Wired optional CLI overrides into normalized run config and `override_source`.
- Added tests for graph, risk and wiki optional override persistence.
- Normalized missing config path into `error: config file not found: ...` with exit code 2 and no traceback.

Review verdict: ACCEPT after REDIRECT-SEQ004-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py plugins/agentic-deep-audit/tests/test_cli_config.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.

## SEQ-003 - Skill Contract And References

Author: Codex.
Reviewer: Nash.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ003-001/P2: top-level ledger status still said seq 002 pending.
- REDIRECT-SEQ003-001/P2: safety policy test did not assert no-exec, network, sanitizer, MCP write policy and host MCP exception coverage.
- REDIRECT-SEQ003-001/P2: adapter contract test did not assert the structured fourth `status` operation.

Remediation:

- Updated top-level status to `seq 003 pending`.
- Strengthened `test_skill_contract.py` safety assertions for all required 003.5 policy areas.
- Strengthened `test_skill_contract.py` adapter assertions to require bullet operations `detect`, `run`, `parse` and `status`.

Review verdict: ACCEPT after REDIRECT-SEQ003-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py plugins/agentic-deep-audit/tests/test_skill_contract.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.

## SEQ-002 - Plugin Scaffold And Packaging

Author: Codex.
Reviewer: Parfit.
Gate: `operator_go`.
Commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`

Blockers:

- REDIRECT-SEQ002-001/P1: commands used mixed working directories.
- REDIRECT-SEQ002-001/P2: top-level ledger status still said seq 001 pending.
- REDIRECT-SEQ002-001/P2: scaffold test did not fail on orphan top-level directories.

Remediation:

- Standardized SEQ-002 commands to repo root.
- Updated top-level status to `seq 002 pending`.
- Added explicit allowed top-level scaffold path test with generated-cache exclusions.

Review verdict: ACCEPT after REDIRECT-SEQ002-001 remediation.
Accepted commands:

- `python -m pytest plugins/agentic-deep-audit/tests/check_gate_paths.py plugins/agentic-deep-audit/tests/test_scaffold.py -v`
- `$env:PYTHONPATH="plugins/agentic-deep-audit/src"; python -m agentic_deep_audit.gate check-paths --base HEAD`
- `git diff --check`

Status: OK.
