# Output Artifacts

Each artifact below is required, optional-with-skipped-rationale, bundled policy, or input as defined by the accepted output matrix. If an artifact cannot be produced, emit the paired skipped/deferred artifact when listed and record the reason in `TOOL_STATUS.json` or `VALIDATION_REPORT.md`.

## Phase 0 And Inputs

- `audit.config.yaml`
- `RUN_CONFIG.json`
- `audit.config.yaml.snapshot`
- `.network_policy.json`
- `.network_policy.json.snapshot`
- `policies/BLOCKED_COMMANDS_ALLOWLIST.json`
- `policies/DEFAULT_NETWORK_POLICY.json`
- `TOOL_STATUS.json`
- `PROGRESS.md`
- `BLOCKED_COMMANDS_ATTEMPTS.json`

## Phase 1

- `FILE_INDEX.json`
- `INVENTORY.md`
- `PROVENANCE.json`
- `EVIDENCE_INDEX.json`

## Phase 2

- `MANIFESTS.json`
- `BUILD_TEST_MAP.md`
- `CI_MAP.json`

## Phase 3

- `MODULE_GRAPH.json`
- `SYMBOL_INDEX.json`
- `CALL_GRAPH.json`
- `CALL_GRAPH_SKIPPED.md`
- `ARCHITECTURE.md`

## Phase 4

- `API_SURFACE.json`
- `CLI_SURFACE.json`
- `MCP_SURFACE.json`
- `CONFIG_SURFACE.json`

## Phase 5

- `FEATURE_CATALOG.md`
- `PATTERNS.md`
- `SPECIAL_IMPLEMENTATIONS.json`
- `PROJECT_TELEMETRY.md`
- `PROJECT_TELEMETRY.json`
- `SCIENTIFIC_PROVENANCE.md`
- `SCIENTIFIC_PROVENANCE.json`

## Phase 6

- `RISK_FINDINGS.json`
- `SUSPICIOUS_BEHAVIORS.json`
- `AGENTIC_SECURITY.md`
- `AGENTIC_SECURITY_FINDINGS.json`
- `RISK_REPORT.md`
- `LICENSE_MATRIX.md`
- `LICENSE_CARDS.json`
- `SBOM.cdx.json`
- `SBOM_SKIPPED.md`
- `SUPPLY_CHAIN_SIGNALS.md`
- `BINARY_ARTIFACTS.json`

## Phase 7

- `PERFORMANCE_REVIEW.md`
- `AUDIT_RUNTIME_METRICS.json`
- `QUALITY_REVIEW.md`
- `TEST_COVERAGE_SIGNAL.md`
- `REUSE_CARDS.json`
- `REUSE_MAP.md`

## Phase 8

- `wiki/000_home.md`
- `wiki/001_repo_summary.md`
- `wiki/002_architecture_overview.md`
- `wiki/003_reuse_index.md`
- `wiki/004_risk_index.md`
- `wiki/modules/*.md`
- `wiki/features/*.md`
- `wiki/patterns/*.md`
- `wiki/risks/*.md`
- `wiki/reuse/*.md`
- `wiki/decisions/*.md`
- `graph/graph.json`
- `graph/nodes.json`
- `graph/edges.json`
- `graph/graph.html`
- `GRAPH_HTML_SKIPPED.md`
- `graphify/*`
- `GRAPHIFY_SKIPPED.md`
- `graphify/GRAPH_REPORT.md`
- `graphify/graph.json`
- `graphify/GRAPHIFY_DIFF.md`
- `CORPUS_INDEX.json`
- `CORPUS.sqlite`
- `CORPUS_SQLITE_SKIPPED.md`
- `mcp/.mcp.json`
- `MCP_DEFERRED.md`
- `MCP_COLLISION_REPORT.md`

## Phase 9 And Release

- `REPORT.md`
- `OPEN_QUESTIONS.md`
- `VALIDATION_REPORT.md`
- `VALIDATION_REPORT.json`
- `ADVERSARIAL_REVIEW_PACKET.md`
- `REVIEW_LEDGER.md`
- `RELEASE_CHECKLIST.md`
- `SEQ_ATOMICITY_REPORT.md`
