"""Generic JSON schema validation for audit artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .models import ARTIFACT_PATHS, load_schema_registry


SCHEMA_BY_ARTIFACT_KEY = {
    "NETWORK_POLICY": "network_policy",
    "TOOL_STATUS": "tool_status",
    "EVIDENCE_INDEX": "evidence_index",
    "MODULE_GRAPH": "module_graph",
    "SYMBOL_INDEX": "symbol_index",
    "CALL_GRAPH": "call_graph",
    "GRAPH": "graph",
    "API_SURFACE": "api_surface",
    "CLI_SURFACE": "cli_surface",
    "MCP_SURFACE": "mcp_surface",
    "CONFIG_SURFACE": "config_surface",
    "SPECIAL_IMPLEMENTATIONS": "special_implementations",
    "RISK_FINDINGS": "risk_findings",
    "SUSPICIOUS_BEHAVIORS": "suspicious_behaviors",
    "AGENTIC_SECURITY_FINDINGS": "agentic_security_finding",
    "LICENSE_CARDS": "license_cards",
    "REUSE_CARDS": "reuse_cards",
    "SCIENTIFIC_PROVENANCE": "scientific_provenance",
    "PROJECT_TELEMETRY": "project_telemetry",
    "AUDIT_RUNTIME_METRICS": "audit_runtime_metrics",
    "BINARY_ARTIFACTS": "binary_artifacts",
    "CORPUS_INDEX": "corpus_index",
}


def schema_by_relative_path() -> dict[str, str]:
    return {ARTIFACT_PATHS[key]: schema for key, schema in SCHEMA_BY_ARTIFACT_KEY.items()}


def load_json_artifact(path: Path, relative: str, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"json_parse: {relative}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"core_envelope: {relative}: JSON root must be object")
        return None
    return payload


def validate_json_artifact_schemas(audit_dir: Path) -> list[str]:
    errors: list[str] = []
    registry = load_schema_registry()
    mapping = schema_by_relative_path()
    for path in sorted(audit_dir.rglob("*.json")):
        relative = path.relative_to(audit_dir).as_posix()
        payload = load_json_artifact(path, relative, errors)
        if payload is None:
            continue
        schema_name = mapping.get(relative)
        if schema_name is None:
            continue
        schema = registry[schema_name].schema
        validator = Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(payload), key=lambda item: list(item.path)):
            location = ".".join(str(part) for part in error.path) or "<root>"
            errors.append(f"{schema_name}_schema: {relative}: {location}: {error.message}")
    return errors
