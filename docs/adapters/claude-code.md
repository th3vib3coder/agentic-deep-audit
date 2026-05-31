# Claude Code Adapter

Status: `first-class-docs`. Claude Code is one of two co-equal primary agent adapters; this is a
docs-first adapter (existing hook metadata, no fabricated Claude CLI wrapper). It declares the nine
required adapter-doc fields from `docs/contracts/adapter_contract.md`.

## adapter id

`claude-code`

## user entry command

Docs-first: follow the **Runbook** below. There is no bespoke executable wrapper — do not assume a
`claude` CLI flag that may not exist in your Claude Code version; drive the engine via the package
CLI as the runbook describes.

## required files

- `.claude-plugin/plugin.json` — the Claude Code manifest (routes to `hooks/hooks.json`).
- `hooks/hooks.json` — the hook settings.
- this runbook and `src/agentic_deep_audit/schemas/`.

## optional files

- `skills/deep-repo-audit/references/`.

## output directory

The portable `audit/` tree in the target repository.

## security model

- target-repo code execution: blocked by runbook (no-exec); follow the runbook unmodified;
- network: denied by default;
- host config access: none unless the operator supplies it;
- credentials: operator-supplied only;
- redaction verification: runbook redaction checklist + artifact scan;
- write permissions: audit output only.

## expected skipped/deferred behavior

Tools absent from the environment are recorded as `skipped`/`degraded` in `TOOL_STATUS.json`;
missing optional tools are never presented as successful coverage.

## validation command

`python -m pytest tests/test_adapter_claude_code_docs.py -q`

## ownership of docs/tests

`tests/test_adapter_claude_code_docs.py` and `tests/test_adapter_docs_contract.py`.

## Runbook

1. Open the target repository in Claude Code.
2. Run the audit through the installed package / CLI as documented (e.g. `deep-audit run --config audit.config.yaml`), keeping the engine's default no-exec, network-deny policy.
3. Review the generated `audit/` artifacts: start from `VALIDATION_REPORT.md`, trace claims through `EVIDENCE_INDEX.json`, and confirm the run via `RUN_CONFIG.json`.

## Safety / no-exec guarantees

The Claude Code adapter does not execute target-repo code by default (no-exec). Follow the runbook
without modification; any deviation requires the governance approval defined in
`docs/contracts/release_process.md`.

## External-review handoff

`ADVERSARIAL_REVIEW_PACKET.md` and `VALIDATION_REPORT.md` are the external-review handoff artifacts.
Claude Code may draft a review but must not self-certify it; the governance procedure lives in
`docs/contracts/release_process.md`.

## One adapter, not the engine

Claude Code is one adapter, not required for CLI or package use: the package installs and runs
without the Claude Code runbook. (SD-2: Codex and Claude Code are co-equal primary adapters.)
