"""Central artifact constants and schema registry helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import read_json_capped
from .resources import SOURCE_PLUGIN_ROOT, schema_dir


PLUGIN_ROOT = SOURCE_PLUGIN_ROOT
SCHEMA_DIR = schema_dir()

RUN_CONFIG = "RUN_CONFIG.json"
TOOL_STATUS = "TOOL_STATUS.json"
PROGRESS = "PROGRESS.md"
VALIDATION_REPORT = "VALIDATION_REPORT.md"
VALIDATION_REPORT_JSON = "VALIDATION_REPORT.json"

ARTIFACT_PATHS: dict[str, str] = {
    "AUDIT_CONFIG": "audit.config.yaml",
    "RUN_CONFIG": RUN_CONFIG,
    "AUDIT_CONFIG_SNAPSHOT": "audit.config.yaml.snapshot",
    "NETWORK_POLICY": ".network_policy.json",
    "NETWORK_POLICY_SNAPSHOT": ".network_policy.json.snapshot",
    "BLOCKED_COMMANDS_ALLOWLIST": "policies/BLOCKED_COMMANDS_ALLOWLIST.json",
    "DEFAULT_NETWORK_POLICY": "policies/DEFAULT_NETWORK_POLICY.json",
    "TOOL_STATUS": TOOL_STATUS,
    "PROGRESS": PROGRESS,
    "BLOCKED_COMMANDS_ATTEMPTS": "BLOCKED_COMMANDS_ATTEMPTS.json",
    "FILE_INDEX": "FILE_INDEX.json",
    "INVENTORY": "INVENTORY.md",
    "PROVENANCE": "PROVENANCE.json",
    "MANIFESTS": "MANIFESTS.json",
    "BUILD_TEST_MAP": "BUILD_TEST_MAP.md",
    "CI_MAP": "CI_MAP.json",
    "EVIDENCE_INDEX": "EVIDENCE_INDEX.json",
    "MODULE_GRAPH": "MODULE_GRAPH.json",
    "SYMBOL_INDEX": "SYMBOL_INDEX.json",
    "CALL_GRAPH": "CALL_GRAPH.json",
    "CALL_GRAPH_SKIPPED": "CALL_GRAPH_SKIPPED.md",
    "ARCHITECTURE": "ARCHITECTURE.md",
    "API_SURFACE": "API_SURFACE.json",
    "CLI_SURFACE": "CLI_SURFACE.json",
    "MCP_SURFACE": "MCP_SURFACE.json",
    "CONFIG_SURFACE": "CONFIG_SURFACE.json",
    "FEATURE_CATALOG": "FEATURE_CATALOG.md",
    "PATTERNS": "PATTERNS.md",
    "SPECIAL_IMPLEMENTATIONS": "SPECIAL_IMPLEMENTATIONS.json",
    "RISK_FINDINGS": "RISK_FINDINGS.json",
    "SUSPICIOUS_BEHAVIORS": "SUSPICIOUS_BEHAVIORS.json",
    "AGENTIC_SECURITY": "AGENTIC_SECURITY.md",
    "AGENTIC_SECURITY_FINDINGS": "AGENTIC_SECURITY_FINDINGS.json",
    "RISK_REPORT": "RISK_REPORT.md",
    "LICENSE_MATRIX": "LICENSE_MATRIX.md",
    "LICENSE_CARDS": "LICENSE_CARDS.json",
    "SBOM": "SBOM.cdx.json",
    "SBOM_SKIPPED": "SBOM_SKIPPED.md",
    "SUPPLY_CHAIN_SIGNALS": "SUPPLY_CHAIN_SIGNALS.md",
    "BINARY_ARTIFACTS": "BINARY_ARTIFACTS.json",
    "PROJECT_TELEMETRY_MD": "PROJECT_TELEMETRY.md",
    "PROJECT_TELEMETRY": "PROJECT_TELEMETRY.json",
    "SCIENTIFIC_PROVENANCE_MD": "SCIENTIFIC_PROVENANCE.md",
    "SCIENTIFIC_PROVENANCE": "SCIENTIFIC_PROVENANCE.json",
    "PERFORMANCE_REVIEW": "PERFORMANCE_REVIEW.md",
    "AUDIT_RUNTIME_METRICS": "AUDIT_RUNTIME_METRICS.json",
    "QUALITY_REVIEW": "QUALITY_REVIEW.md",
    "TEST_COVERAGE_SIGNAL": "TEST_COVERAGE_SIGNAL.md",
    "WIKI_HOME": "wiki/000_home.md",
    "WIKI_REPO_SUMMARY": "wiki/001_repo_summary.md",
    "WIKI_ARCHITECTURE": "wiki/002_architecture_overview.md",
    "WIKI_REUSE_INDEX": "wiki/003_reuse_index.md",
    "WIKI_RISK_INDEX": "wiki/004_risk_index.md",
    "WIKI_MODULES": "wiki/modules/*.md",
    "WIKI_FEATURES": "wiki/features/*.md",
    "WIKI_PATTERNS": "wiki/patterns/*.md",
    "WIKI_RISKS": "wiki/risks/*.md",
    "WIKI_REUSE": "wiki/reuse/*.md",
    "WIKI_DECISIONS": "wiki/decisions/*.md",
    "GRAPH": "graph/graph.json",
    "GRAPH_NODES": "graph/nodes.json",
    "GRAPH_EDGES": "graph/edges.json",
    "GRAPH_HTML": "graph/graph.html",
    "GRAPH_HTML_SKIPPED": "GRAPH_HTML_SKIPPED.md",
    "GRAPHIFY_WILDCARD": "graphify/*",
    "GRAPHIFY_SKIPPED": "GRAPHIFY_SKIPPED.md",
    "GRAPHIFY_REPORT": "graphify/GRAPH_REPORT.md",
    "GRAPHIFY_GRAPH": "graphify/graph.json",
    "GRAPHIFY_DIFF": "graphify/GRAPHIFY_DIFF.md",
    "CORPUS_INDEX": "CORPUS_INDEX.json",
    "CORPUS_SQLITE": "CORPUS.sqlite",
    "CORPUS_SQLITE_SKIPPED": "CORPUS_SQLITE_SKIPPED.md",
    "REUSE_CARDS": "REUSE_CARDS.json",
    "REUSE_MAP": "REUSE_MAP.md",
    "MCP_CONFIG": "mcp/.mcp.json",
    "MCP_DEFERRED": "MCP_DEFERRED.md",
    "MCP_COLLISION_REPORT": "MCP_COLLISION_REPORT.md",
    "REPORT": "REPORT.md",
    "OPEN_QUESTIONS": "OPEN_QUESTIONS.md",
    "VALIDATION_REPORT": VALIDATION_REPORT,
    "VALIDATION_REPORT_JSON": VALIDATION_REPORT_JSON,
    "ADVERSARIAL_REVIEW_PACKET": "ADVERSARIAL_REVIEW_PACKET.md",
    "REVIEW_LEDGER": "REVIEW_LEDGER.md",
    "RELEASE_CHECKLIST": "RELEASE_CHECKLIST.md",
    "SEQ_ATOMICITY_REPORT": "SEQ_ATOMICITY_REPORT.md",
}

SCHEMA_FILES: dict[str, str] = {
    "audit_config": "audit_config.schema.json",
    "run_config": "run_config.schema.json",
    "network_policy": "network_policy.schema.json",
    "blocked_commands": "blocked_commands.schema.json",
    "file_index": "file_index.schema.json",
    "provenance": "provenance.schema.json",
    "manifests": "manifests.schema.json",
    "evidence_index": "evidence_index.schema.json",
    "tool_status": "tool_status.schema.json",
    "module_graph": "module_graph.schema.json",
    "symbol_index": "symbol_index.schema.json",
    "call_graph": "call_graph.schema.json",
    "graph": "graph.schema.json",
    "api_surface": "api_surface.schema.json",
    "cli_surface": "cli_surface.schema.json",
    "mcp_surface": "mcp_surface.schema.json",
    "config_surface": "config_surface.schema.json",
    "special_implementations": "special_implementations.schema.json",
    "risk_findings": "risk_findings.schema.json",
    "suspicious_behaviors": "suspicious_behaviors.schema.json",
    "agentic_security_finding": "agentic_security_finding.schema.json",
    "license_cards": "license_cards.schema.json",
    "reuse_cards": "reuse_cards.schema.json",
    "scientific_provenance": "scientific_provenance.schema.json",
    "project_telemetry": "project_telemetry.schema.json",
    "audit_runtime_metrics": "audit_runtime_metrics.schema.json",
    "binary_artifacts": "binary_artifacts.schema.json",
    "corpus_index": "corpus_index.schema.json",
    "adapter_decision": "adapter_decision.schema.json",
    "core_envelope": "core_envelope.schema.json",
    "mcp_config": "mcp_config.schema.json",
}


class SchemaRegistryError(ValueError):
    """Raised when bundled schemas cannot be loaded."""


@dataclass(frozen=True)
class SchemaRecord:
    name: str
    filename: str
    path: Path
    schema: dict[str, Any]


def _validate_schema_shape(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SchemaRegistryError(f"{name}: schema root must be an object")
    for key in ["$schema", "title", "type", "properties"]:
        if key not in value:
            raise SchemaRegistryError(f"{name}: missing schema key {key}")
    if value["type"] != "object":
        raise SchemaRegistryError(f"{name}: root type must be object")
    if not isinstance(value["properties"], dict):
        raise SchemaRegistryError(f"{name}: properties must be an object")
    return value


def load_schema_registry(schema_dir: Path | None = None) -> dict[str, SchemaRecord]:
    schema_root = schema_dir or schema_dir_default()
    registry: dict[str, SchemaRecord] = {}
    for name, filename in SCHEMA_FILES.items():
        path = schema_root / filename
        try:
            raw = read_json_capped(path, label="schema registry")
        except Exception as exc:  # noqa: BLE001 - preserve path/schema name in error.
            raise SchemaRegistryError(f"{name}: failed to load {path}: {exc}") from exc
        try:
            schema = _validate_schema_shape(name, raw)
        except SchemaRegistryError as exc:
            raise SchemaRegistryError(f"{name}: invalid schema shape in {path}: {exc}") from exc
        registry[name] = SchemaRecord(name=name, filename=filename, path=path, schema=schema)
    return registry


def schema_dir_default() -> Path:
    return schema_dir()
