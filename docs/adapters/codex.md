# Codex Adapter

Status: `documented-beta`. Codex is one of two co-equal primary agent adapters (the other is
Claude Code); neither is the engine. This doc declares the nine required adapter-doc fields from
`docs/contracts/adapter_contract.md`. Do not mark `first-class`/`verified`/`supported` without
recorded evidence.

## adapter id

`codex`

## user entry command

Invoke the bundled `deep-repo-audit` skill from Codex — the `.codex-plugin/plugin.json` manifest
routes to `skills/deep-repo-audit/SKILL.md`. The skill drives the same engine the CLI uses.

## required files

- `.codex-plugin/plugin.json` — the Codex manifest.
- `skills/deep-repo-audit/SKILL.md` — the skill entry.
- `src/agentic_deep_audit/schemas/` — runtime schemas.

## optional files

- `skills/deep-repo-audit/references/` — supporting reference material.

## output directory

The portable `audit/` tree in the target repository.

## security model

- target-repo code execution: blocked by default;
- network: denied by default;
- host config access: Codex config only via explicit policy;
- credentials: Codex-managed, redacted before write;
- redaction verification: Codex adapter tests + artifact scan;
- write permissions: plugin package + audit output only.

## Security

The seven adapter security columns for `codex`:

| target execution | network default | host config access | credentials | redaction verification | no-exec enforcement | write permissions |
|---|---|---|---|---|---|---|
| none (static, read-only audit; never executes target-repo code) | denied (default-deny network policy) | reads host MCP config as read-only metadata for collision detection only | none read beyond redacted metadata | covered by the provenance/MCP redaction tests and the artifact scan | the PreToolUse hook blocks command execution; the engine performs no target-repo execution | confined to the generated `audit/` output tree |

## expected skipped/deferred behavior

Tools absent from the Codex environment are recorded as `skipped`/`degraded` in `TOOL_STATUS.json`;
missing optional tools are never presented as successful coverage.

## validation command

`python -m pytest tests/test_adapter_codex.py -q`

## ownership of docs/tests

`tests/test_adapter_codex.py` and `tests/test_adapter_docs_contract.py`.

## One adapter, not the engine

Codex is one adapter, not required for CLI or package use: the package installs and runs without
`.codex-plugin/` present. (SD-2: Codex and Claude Code are co-equal primary adapters; neither is
"the" host.)
