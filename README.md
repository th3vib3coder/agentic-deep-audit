# Agentic Deep Audit

Agentic Deep Audit is a Codex v1 plugin for evidence-first audits of local and GitHub open-source repositories. It produces portable `audit/` artifacts for human review, external adversarial review, Obsidian-style wiki navigation, graph exports, corpus retrieval and optional read-only MCP handoff.

The default mode treats the target repository as untrusted input. It reads files, records evidence and does not execute target repository code, install scripts, tests, hooks, MCP configs or manifest commands.

## Quick Start

```powershell
$env:PYTHONPATH = "src"
python -m agentic_deep_audit.cli run --config audit.config.yaml
python -m agentic_deep_audit.cli validate --audit-dir audit
```

Installed package alias:

```bash
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
```

Use `--run-config audit/RUN_CONFIG.json` for a reproducible rerun from normalized config.

## Profiles

| Profile | Produced outputs | Skipped or gated outputs |
|---|---|---|
| Minimal Offline | inventory, provenance, manifest map, static graph, surfaces, synthesis, wiki, corpus when SQLite FTS5 is available, validation report | GitHub/network metadata skipped without policy; Graphify and MCP may be skipped/deferred |
| Standard Local | Minimal outputs plus SBOM when Syft/cdxgen is available, local SAST adapter results when promoted, license scan, supported-language module graph, SQLite+FTS5 corpus with hybrid retrieval, Graphify output or fallback/skipped note, and deeper risk report | SBOM/SAST/Graphify are skipped or deferred when tools are unavailable or unpromoted; external CVE/package services remain gated |
| Extended With MCP/Cloud | Standard outputs plus GitHub metadata, issue/PR/release/CI insight, current CVE/advisory data, external scorecards, advanced graph/code intelligence, and optional read-only `mcp/.mcp.json` or `MCP_DEFERRED.md`/`MCP_COLLISION_REPORT.md` | requires `.network_policy.json`, scope-limited credentials and redaction; host MCP collision or secret uncertainty fails closed |
| Research/Binary | Standard outputs plus binary artifact triage and scientific provenance when explicit signals exist | binary triage requires `binary_triage_consent`; scientific claims require structured provenance or open questions |

`TOOL_STATUS.json` is the source of observed truth for a specific run. Profile tables describe expected behavior, not proof that a tool was present on the current OS.

## Windows And OS Fallbacks

The core path uses Python stdlib, Git and ripgrep when available. Missing optional tools are recorded as `skipped`, `deferred` or `degraded` in `TOOL_STATUS.json`. Windows runs use the same artifact contracts; path-specific differences are captured in `RUN_CONFIG.json` provenance and tool status records.

SQLite FTS5, Git metadata, Graphify and MCP availability are runtime observations. A missing tool must produce a skipped/deferred artifact or a validation blocker, not an implicit success.

## Adapter Promotion

Optional tools are prior art until promoted. Promotion requires `docs/adapters/<tool>/adapter_decision.json` with installability, license, version pinning, read-only command, policy, observed output schema, fallback, decision and independent reviewer. `docs/adapters/ADAPTER_EVALUATION.md` is the human review card; the JSON decision is the machine-checkable gate.

Graphify remains optional and isolated from canonical `graph/graph.json` unless its adapter decision says `promote`. Source-claim tools are not accepted dependencies in this package.

## Non-Claims

This plugin does not provide legal advice, prove license compatibility, certify absence of vulnerabilities, guarantee production safety or execute untrusted repository code. Security, license, performance and scientific conclusions must remain evidence-linked, scoped by profile and caveated by generated audit artifacts.
