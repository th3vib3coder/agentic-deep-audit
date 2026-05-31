# CLI Adapter

Status: `documented-beta`. The CLI is the primary engine-neutral entry surface: it requires no
host agent (neither Codex nor Claude Code) and no private workspace path. It is tested and
documented, but `first-class` requires recorded Windows+Linux OS release evidence (see the
promotion rules and the closed status enum in `docs/contracts/adapter_contract.md`); that
promotion happens in the release phase once the evidence exists. Do not market the CLI as
`first-class`, `verified` or `supported` until that evidence is recorded.

This adapter declares the nine required adapter-doc fields from `docs/contracts/adapter_contract.md`.

## adapter id

`cli`

## user entry command

- Installed: `deep-audit run --config audit.config.yaml`
- From a source checkout: `PYTHONPATH=src python -m agentic_deep_audit.cli run --config audit.config.yaml`

Run from the package root. A previously generated run config can be replayed with
`deep-audit run --run-config RUN_CONFIG.json`.

## required files

- `pyproject.toml` — package metadata and the `deep-audit` console entry point.
- `src/agentic_deep_audit/` — the engine package.

## optional files

- an audit config (`audit.config.yaml`), or `--run-config RUN_CONFIG.json` to replay a prior config;
- a validated `.network_policy.json` to allow specific domains (network is denied by default).

## output directory

The portable `audit/` tree by default (overridable with `--output-dir`). The generated
`RUN_CONFIG.json` records `schema_version` and a `launch_surface` block with `adapter: cli`.

## security model

- target-repo code execution: blocked by default (install scripts, tests, hooks and manifest
  commands are parsed and recorded, never run);
- network: denied unless a validated `.network_policy.json` allows it;
- host config access: none;
- credentials: supplied via config/env only when policy allows;
- redaction verification: covered by the redaction-scan tests and the pre-tool policy;
- write permissions: audit output only.

## Security

The seven adapter security columns for `cli`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (static, read-only audit; target-repo install scripts, tests, hooks and manifest commands are parsed and recorded, never run) | denied (default-deny; a validated `.network_policy.json` may allow specific domains) | none | none read (config/env values are supplied by the operator only when policy allows) | covered by the provenance/redaction-scan tests and the pre-tool policy | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the generated `audit/` output tree |

## expected skipped/deferred behavior

Unavailable optional tools (git, ripgrep, graph/corpus extras) are recorded as `skipped` or
`degraded` in `TOOL_STATUS.json` with a reason; macOS and the container adapter are `deferred`.
Missing optional tools are never presented as successful coverage.

## validation command

`python -m pytest tests/test_validate_cli.py -q`

## ownership of docs/tests

`tests/test_validate_cli.py` and `tests/test_adapter_docs_contract.py` own this adapter's
documentation and behavior.
