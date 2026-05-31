# Agentic Deep Audit

[![CI](https://github.com/th3vib3coder/agentic-deep-audit/actions/workflows/agentic-deep-audit.yml/badge.svg)](https://github.com/th3vib3coder/agentic-deep-audit/actions/workflows/agentic-deep-audit.yml)

Agentic Deep Audit is an evidence-first repository audit engine for local and GitHub open-source projects. It combines a Python CLI, a packaged audit skill, Codex and Claude Code host metadata, read-only MCP handoff, schema validation, adversarial review artifacts and portable `audit/` outputs.

The default model treats the target repository as untrusted input. It reads files, records provenance, hashes and evidence ranges, and does **not** execute target repository code, install scripts, package scripts, tests, hooks, MCP configs or CI commands discovered inside the target.

## Contents

- [What It Produces](#what-it-produces)
- [Safety Model](#safety-model)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Commands](#cli-commands)
- [Profiles](#profiles)
- [Major Functional Areas](#major-functional-areas)
- [Codex, Claude Code And MCP Integration](#codex-claude-code-and-mcp-integration)
- [Adapter Promotion And Optional Tools](#adapter-promotion-and-optional-tools)
- [Validation And Review Workflow](#validation-and-review-workflow)
- [Development Checks](#development-checks)
- [Non-Claims](#non-claims)

## What It Produces

A full `deep-audit run` creates a structured audit directory. The exact set depends on profile, tool availability and policy, but the artifact contract includes:

- run bootstrap: `RUN_CONFIG.json`, `TOOL_STATUS.json`, `PROGRESS.md`, config and policy snapshots;
- inventory and provenance: `FILE_INDEX.json`, `INVENTORY.md`, `PROVENANCE.json`, `EVIDENCE_INDEX.json`;
- manifest and CI maps: `MANIFESTS.json`, `BUILD_TEST_MAP.md`, `CI_MAP.json`;
- code structure: `MODULE_GRAPH.json`, `SYMBOL_INDEX.json`, canonical `graph/graph.json`, `graph/nodes.json`, `graph/edges.json`;
- public surfaces: `API_SURFACE.json`, `CLI_SURFACE.json`, `MCP_SURFACE.json`, `CONFIG_SURFACE.json`;
- synthesis: `ARCHITECTURE.md`, `FEATURE_CATALOG.md`, `PATTERNS.md`, `SPECIAL_IMPLEMENTATIONS.json`;
- scientific and telemetry signals: `SCIENTIFIC_PROVENANCE.json/.md`, `PROJECT_TELEMETRY.json/.md`;
- risk, supply-chain, license and binary signals: `RISK_FINDINGS.json`, `SUSPICIOUS_BEHAVIORS.json`, `AGENTIC_SECURITY.md`, `LICENSE_MATRIX.md`, `LICENSE_CARDS.json`, `SBOM_SKIPPED.md`, `BINARY_ARTIFACTS.json`;
- quality and reuse: `PERFORMANCE_REVIEW.md`, `QUALITY_REVIEW.md`, `TEST_COVERAGE_SIGNAL.md`, `REUSE_CARDS.json`, `REUSE_MAP.md`;
- navigation and retrieval: Obsidian-style `wiki/`, `CORPUS_INDEX.json`, optional `CORPUS.sqlite` with SQLite+FTS5;
- optional handoff: read-only `mcp/.mcp.json`, or `MCP_DEFERRED.md` / `MCP_COLLISION_REPORT.md`;
- closure packet: `VALIDATION_REPORT.md/.json`, `REPORT.md`, `OPEN_QUESTIONS.md`, `REVIEW_LEDGER.md`, `ADVERSARIAL_REVIEW_PACKET.md`.

If an optional artifact cannot be produced, the plugin should emit an explicit skipped/deferred artifact or a `TOOL_STATUS.json` entry. Missing optional tools must not be presented as successful coverage.

## Safety Model

Agentic Deep Audit is designed for untrusted repositories:

- target source is data, not instructions;
- target commands are parsed and recorded, not executed;
- host MCP configs are inspected only for collision metadata and are never imported into the host agent config;
- network access is denied unless a validated `.network_policy.json` allows it;
- denied domains and redaction rules fail closed;
- binary triage is disabled unless `binary_triage_consent` is explicit;
- Markdown from the target is sanitized before it can enter LLM context;
- blocked command/tool attempts are recorded in `BLOCKED_COMMANDS_ATTEMPTS.json` with secret redaction.

## Installation

### Requirements

- Python `>=3.10`.
- Platforms: continuously tested in CI (GitHub Actions) on `ubuntu-latest` and `windows-latest` across Python 3.10, 3.11 and 3.12; `macos-latest` is currently `deferred` with no active CI job.
- Runtime dependencies declared in `pyproject.toml`:
  - `defusedxml`
  - `jsonschema`
  - `PyYAML`
  - `tomli` on Python `<3.11`
- Optional external tools are detected at runtime and recorded in `TOOL_STATUS.json`:
  - Git and ripgrep improve provenance/inventory where available;
  - SQLite FTS5 enables the corpus database;
  - Syft/cdxgen, Graphify, SAST/CVE tools and other adapters remain skipped/deferred unless available and promoted.

### Install From A Git Checkout

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
```

### Run From Source Without Installing

Use this only for local development or a checkout where dependencies are already installed:

```powershell
$env:PYTHONPATH = "src"
python -m agentic_deep_audit.cli run --config audit.config.yaml
python -m agentic_deep_audit.cli validate --audit-dir audit
```

On POSIX shells:

```bash
PYTHONPATH=src python -m agentic_deep_audit.cli run --config audit.config.yaml
PYTHONPATH=src python -m agentic_deep_audit.cli validate --audit-dir audit
```

### Install From A Wheel

If you have a built wheel:

```bash
python -m pip install agentic_deep_audit-*.whl
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
```

The console entry point is:

```text
deep-audit = agentic_deep_audit.cli:main
```

## Quick Start

Create `audit.config.yaml` in the target repository:

```yaml
schema_version: "1.0"
repo:
  kind: "local"
  path: "."
  github: null
profile: "standard"
mode: "source-audit"
output_dir: "audit"
target_context: "MIT downstream"
binary_triage_consent: false
```

Run the audit and validation:

```bash
deep-audit run --config audit.config.yaml
deep-audit validate --audit-dir audit
```

For a deterministic rerun from normalized config:

```bash
deep-audit run --run-config audit/RUN_CONFIG.json --output-dir audit-rerun
deep-audit validate --audit-dir audit-rerun
```

Preview planned outputs without writing artifacts:

```bash
deep-audit run --config audit.config.yaml --dry-run
```

## Configuration

Required config fields:

| Field | Meaning |
|---|---|
| `schema_version` | Config schema version string. |
| `repo.kind` | `local` or `github`. |
| `repo.path` | Local repository path for local audits. |
| `repo.github` | GitHub repository identifier/URL when applicable. |
| `profile` | One of `minimal`, `standard`, `extended`, `research`. |
| `mode` | `source-audit` or `binary-triage`. |
| `output_dir` | Audit artifact directory, usually `audit`. |
| `target_context` | Reuse/license context preset or object. |
| `binary_triage_consent` | Required boolean gate for binary triage. |

Common optional fields:

- `scope_filters`: include/exclude controls for repository scanning.
- `network_policy_file`: path to `.network_policy.json`.
- `mcp_config.host_config_paths`: bounded list of host MCP configs to inspect for collisions.
- `blocked_tools` / `blocked_commands_file`: host pre-tool blocking policy.
- `graph`: graph renderer and Graphify options.
- `security`: risk/security adapter settings.
- `retrieval`: corpus retrieval options.

Network policy example:

```json
{
  "schema_version": "1.0",
  "default": "deny",
  "allowed_domains": ["api.github.com"],
  "denied_domains": ["*"],
  "rate_limits": [],
  "redaction_rules": ["token", "authorization", "cookie", "set-cookie"],
  "send_source_code": false,
  "send_dependency_names": true
}
```

With no explicit policy, network work remains skipped or blocked.

## CLI Commands

All config-backed commands require exactly one primary source: `--config` or `--run-config`.

| Command | Purpose |
|---|---|
| `run` | Full pipeline: inventory, provenance, manifests, graph, surface, synthesis, scientific, telemetry, risk/license/binary, quality, reuse, wiki, canonical graph, corpus and MCP export/defer. |
| `inventory` | Bootstrap, inventory, provenance and manifest/CI extraction. |
| `graph` | Inventory/provenance/manifests plus module graph, symbol index and canonical graph outputs. |
| `surface` | Graph prerequisites plus API/CLI/MCP/config/environment surfaces. |
| `synthesis` | Surface prerequisites plus architecture, feature, pattern and special-implementation synthesis. |
| `scientific` | Synthesis prerequisites plus scientific provenance detection and report. |
| `telemetry` | Inventory/provenance/manifests plus project telemetry. |
| `risk` | Inventory/provenance/manifests plus risk, license, supply-chain and binary signals. |
| `wiki` | Full wiki/corpus-oriented path without MCP export. |
| `validate` | Validate schemas, safety gates, evidence coverage and closure artifacts, then emit report/review packet when ready. |

Common options:

- `--profile minimal|standard|extended|research`
- `--output-dir <path>`
- `--allowed-root <path>` repeatable containment override
- `--allow-system-roots` explicit unsafe-root override
- `--dry-run`

Graph-specific options:

- `--renderer <name>`
- `--graphify`
- `--graph-centrality <mode>`

Risk/network option:

- `--network-policy <path>`

Wiki option:

- `--graph-source <path>`

## Profiles

Profile selection controls expected depth, not truth status. `TOOL_STATUS.json` is the source of observed truth for a concrete run.

| Profile | Produced outputs | Skipped or gated outputs |
|---|---|---|
| Minimal Offline | Config normalization, inventory, provenance, manifests, static graph, public surfaces, synthesis, wiki, canonical graph, corpus when SQLite FTS5 is available, validation report. | GitHub metadata without policy, Graphify, MCP host writes, binary triage and external security tooling. |
| Standard Local | Minimal outputs plus SBOM when Syft/cdxgen is available, local SAST results when promoted, license scan, supported-language module graph, SQLite+FTS5 corpus with hybrid retrieval, Graphify output or fallback/skipped note, deeper risk report. | SBOM, SAST and Graphify are skipped/deferred when tools are unavailable, unpromoted or policy-blocked; external CVE/package/cloud services remain gated. |
| Extended With MCP/Cloud | Standard outputs plus GitHub metadata, issue/PR/release/CI insight, current CVE/advisory data, external scorecards, advanced graph/code intelligence and optional read-only MCP config. | Requires `.network_policy.json`, scoped credentials and deterministic redaction; host MCP collision or unreadable host config produces `MCP_DEFERRED.md` or `MCP_COLLISION_REPORT.md`. |
| Research/Binary | Standard outputs plus binary artifact triage and scientific provenance when explicit signals exist. | Binary analysis requires `binary_triage_consent`; scientific claims require provenance records or open questions. |

Windows uses the same Python package and artifact contracts. Missing optional commands, path differences and OS-specific fallbacks must be recorded as skipped/degraded rather than hidden.

## Major Functional Areas

### Inventory And Evidence

- Enumerates files without following symlink escapes.
- Records hashes, sizes, binary flags and read failures.
- Builds `EVIDENCE_INDEX.json` with evidence ids and byte ranges for downstream claims.

### Provenance

- Captures Git metadata with hardened environment and allowlisted commands.
- Records local/GitHub provenance signals when policy permits.
- Redacts secrets in remotes, host metadata and blocked attempts.

### Manifests, Build And CI

- Parses manifests, lockfiles, package scripts, build files and workflow files as data.
- Extracts build/test commands and CI maps without executing discovered commands.
- Uses `defusedxml` for XML-like manifests.

### Graph And Surface Extraction

- Builds module graph and symbol index.
- Emits canonical graph JSON and node/edge exports.
- Extracts API, CLI, MCP, plugin, config and environment surfaces.
- Keeps optional Graphify output isolated from canonical `graph/graph.json`.

### Synthesis, Wiki And Corpus

- Produces evidence-linked architecture, feature, pattern and special-implementation summaries.
- Generates Obsidian-compatible wiki pages.
- Builds a corpus index and optional SQLite+FTS5 database for hybrid retrieval.

### Scientific Provenance

- Detects scientific pipeline/tool/genome/annotation/normalization/parameter signals.
- Detects dataset/citation signals such as DOI, PMID, GEO, SRA/ENA/BioProject and UniProt-style accessions when present.
- Requires scientific claims in report/wiki text to be backed by scientific provenance records or open questions.

### Risk, Supply Chain, License And Binary Signals

- Produces heuristic risk and agentic-security artifacts with evidence ids.
- Parses license files and manifests into license cards/matrix.
- Records SBOM skipped state unless supported tools are present and policy allows them.
- Performs binary triage only with explicit consent.

### Quality, Performance And Reuse

- Separates observed performance data from static proxies.
- Produces quality and test-coverage signals.
- Builds context-aware reuse cards where the tool recommends and the human decision remains `pending`.
- Includes legal, security and performance caveats in reuse artifacts.

## Codex, Claude Code And MCP Integration

This repository includes host metadata for Codex and Claude Code:

- `.codex-plugin/plugin.json` points to `skills/deep-repo-audit/SKILL.md` and `hooks/hooks.json`.
- `.claude-plugin/plugin.json` points Claude Code to `hooks/hooks.json`.
- `skills/deep-repo-audit/SKILL.md` describes the audit workflow, profiles, safety policy and artifact contract.

Claude Code hook integration requires:

```powershell
$env:AGENTIC_DEEP_AUDIT_PYTHON = "C:\path\to\.venv\Scripts\python.exe"
```

or POSIX:

```bash
export AGENTIC_DEEP_AUDIT_PYTHON=/path/to/.venv/bin/python
```

The hook fails closed with `hook_misconfigured` if `AGENTIC_DEEP_AUDIT_PYTHON` is missing. Hook policy blocks risky shell/MCP/write tools before they can act and records blocked attempts with redaction.

MCP output is audit-only and read-only:

- generated `mcp/.mcp.json` exposes audit corpus/graph artifacts, not target repository write access;
- host MCP configs are inspected for collision metadata only;
- collisions, unreadable host configs, dynamic remote configs or secret uncertainty produce `MCP_DEFERRED.md` or `MCP_COLLISION_REPORT.md`.

## Adapter Promotion And Optional Tools

Optional tools are prior art until promoted. Adapter promotion requires:

- `docs/adapters/<tool>/adapter_decision.json`;
- installability notes;
- license compatibility statement;
- version pinning strategy;
- read-only command;
- policy controls;
- observed output schema/sample hash;
- fallback behavior;
- `decision` of `promote`, `defer` or `reject`;
- independent reviewer.

`docs/adapters/ADAPTER_EVALUATION.md` is the human review card. The JSON decision is the machine-checkable gate.

Each integration surface has a dedicated adapter doc under `docs/adapters/` — `cli`, `python-api`, `codex`, `claude-code`, `mcp`, `github-actions`, `ci`, `container` and `package-managers` — and every one carries a seven-column security matrix (target execution, network default, host config access, credentials, redaction verification, no-exec enforcement, write permissions) whose contract lives in `docs/contracts/adapter_contract.md`.

Graphify remains optional and isolated from canonical graph outputs unless its adapter decision says `promote`. Source-claim tools are not accepted dependencies in this package.

## Validation And Review Workflow

Validation checks:

- JSON schema contracts;
- semantic validator parity;
- evidence id reachability;
- markdown artifact hygiene;
- wiki link/frontmatter coverage;
- MCP read-only and collision constraints;
- anti-overclaim language;
- report/review packet readiness.

Run:

```bash
deep-audit validate --audit-dir audit
```

When validation passes and the run is completion-ready, the package can emit:

- `REPORT.md`
- `OPEN_QUESTIONS.md`
- `REVIEW_LEDGER.md`
- `ADVERSARIAL_REVIEW_PACKET.md`

The project follows adversarial review discipline: an author of an implementation or remediation must not issue final ACCEPT on that same artifact. External reviewers should ground findings in the generated artifacts and source evidence, not only in prose reports.

## Development Checks

From a source checkout:

```bash
python -m pip install -e .
python -m pytest tests -q
python -m compileall -q src
git diff --check
```

Focused checks commonly used before release:

```bash
python -m pytest tests/test_release_packaging.py -q
python -m pytest tests/test_pre_tool_policy.py tests/test_network_policy.py tests/test_fixture_mcp_policy.py -q
python -m pytest tests/test_wiki_pages.py tests/test_corpus_retrieval.py -q
python tests/run_smoke_tests.py --report audit/SMOKE_TEST_REPORT.md
```

For schema changes, keep both schema copies byte-identical:

- runtime/package schemas: `src/agentic_deep_audit/schemas/`;
- skill-bundle schemas: `skills/deep-repo-audit/schemas/`.

## Non-Claims

Agentic Deep Audit does not provide legal advice, prove license compatibility, prove absence of vulnerabilities, guarantee production safety or execute untrusted repository code. Security, license, performance and scientific conclusions must remain evidence-linked, profile-scoped and caveated by generated audit artifacts.
