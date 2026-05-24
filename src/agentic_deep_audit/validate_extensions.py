"""Dispatcher for optional domain-specific artifact validators."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS
from .validate_canonical_graph import validate_canonical_graph_artifacts
from .validate_corpus import validate_corpus_artifacts
from .validate_license_binary import validate_license_binary_artifacts
from .validate_mcp_export import validate_mcp_artifacts
from .validate_quality import validate_performance_quality_artifacts
from .validate_report_packet import validate_report_artifacts
from .validate_reuse import validate_reuse_artifacts
from .validate_risk import validate_risk_artifacts
from .validate_scientific import validate_scientific_provenance_artifacts
from .validate_telemetry import validate_project_telemetry_artifacts
from .validate_wiki import validate_wiki_artifacts


SCIENTIFIC_KEYS = ["SCIENTIFIC_PROVENANCE", "SCIENTIFIC_PROVENANCE_MD"]
TELEMETRY_KEYS = ["PROJECT_TELEMETRY", "PROJECT_TELEMETRY_MD"]
RISK_KEYS = ["SUSPICIOUS_BEHAVIORS", "RISK_FINDINGS", "AGENTIC_SECURITY_FINDINGS", "AGENTIC_SECURITY", "SUPPLY_CHAIN_SIGNALS", "RISK_REPORT"]
LICENSE_BINARY_KEYS = ["LICENSE_CARDS", "LICENSE_MATRIX", "SBOM", "SBOM_SKIPPED", "BINARY_ARTIFACTS"]
PERFORMANCE_QUALITY_KEYS = ["PERFORMANCE_REVIEW", "QUALITY_REVIEW", "TEST_COVERAGE_SIGNAL", "AUDIT_RUNTIME_METRICS"]
REUSE_KEYS = ["REUSE_CARDS", "REUSE_MAP"]
WIKI_KEYS = ["WIKI_HOME", "WIKI_REPO_SUMMARY", "WIKI_ARCHITECTURE", "WIKI_REUSE_INDEX", "WIKI_RISK_INDEX"]
GRAPH_KEYS = ["GRAPH", "GRAPH_NODES", "GRAPH_EDGES", "GRAPH_HTML", "GRAPH_HTML_SKIPPED", "GRAPHIFY_SKIPPED", "GRAPHIFY_GRAPH"]
CORPUS_KEYS = ["CORPUS_INDEX", "CORPUS_SQLITE", "CORPUS_SQLITE_SKIPPED"]
MCP_EXPORT_KEYS = ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"]
REPORT_KEYS = ["REPORT", "ADVERSARIAL_REVIEW_PACKET", "REVIEW_LEDGER"]


def any_artifact_exists(audit_dir: Path, keys: list[str]) -> bool:
    return any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in keys)


def extension_artifacts_present(audit_dir: Path) -> bool:
    return any_artifact_exists(audit_dir, SCIENTIFIC_KEYS + TELEMETRY_KEYS + RISK_KEYS + LICENSE_BINARY_KEYS + PERFORMANCE_QUALITY_KEYS + REUSE_KEYS + WIKI_KEYS + GRAPH_KEYS + CORPUS_KEYS + MCP_EXPORT_KEYS + REPORT_KEYS)


def validate_extension_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if any_artifact_exists(audit_dir, SCIENTIFIC_KEYS):
        errors.extend(validate_scientific_provenance_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, TELEMETRY_KEYS):
        errors.extend(validate_project_telemetry_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, RISK_KEYS):
        errors.extend(validate_risk_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, LICENSE_BINARY_KEYS):
        errors.extend(validate_license_binary_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, PERFORMANCE_QUALITY_KEYS):
        errors.extend(validate_performance_quality_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, REUSE_KEYS):
        errors.extend(validate_reuse_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, WIKI_KEYS):
        errors.extend(validate_wiki_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, GRAPH_KEYS):
        errors.extend(validate_canonical_graph_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, CORPUS_KEYS):
        errors.extend(validate_corpus_artifacts(audit_dir, evidence_index))
    errors.extend(validate_mcp_artifacts(audit_dir, evidence_index))
    if any_artifact_exists(audit_dir, REPORT_KEYS):
        errors.extend(validate_report_artifacts(audit_dir))
    return errors
