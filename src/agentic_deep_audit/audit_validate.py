"""Validation helpers for audit output artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .audit_evidence import sha256_range, validate_claims_reach_evidence
from .audit_validate_common import ValidationResult, load_json
from .audit_validate_evidence import (
    is_safe_relative_evidence_path,
    resolve_evidence_source,
    validate_cross_artifact_evidence_references,
    validate_evidence_provenance_drift,
    validate_provenance_artifact,
    validate_synthesis_artifacts,
)
from .validate_claim_language import validate_anti_overclaim_language
from .validate_json_schema import validate_json_artifact_schemas
from .bootstrap import PHASES
from .config import sha256_file
from .audit_inventory import KIND_VALUES
from .mcp_policy import looks_secret
from .models import ARTIFACT_PATHS
from .validate_extensions import extension_artifacts_present, validate_extension_artifacts


BYTE_RANGE_REQUIRED_KINDS = {"file_line", "file_range", "symbol_span", "file_range_binary_safe"}


def validate_tool_status(payload: dict[str, Any], errors: list[str]) -> None:
    tools = payload.get("tools")
    if not isinstance(tools, list):
        errors.append("TOOL_STATUS.json requires tools array")
        return
    by_name = {tool.get("tool"): tool for tool in tools if isinstance(tool, dict)}
    for required in ["python", "git", "rg", "sqlite_fts5", "network_policy"]:
        if required not in by_name:
            errors.append(f"TOOL_STATUS.json missing tool: {required}")
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            errors.append(f"TOOL_STATUS.json tools[{index}] must be object")
            continue
        for key in ["tool", "status", "policy"]:
            if key not in tool:
                errors.append(f"TOOL_STATUS.json tools[{index}] missing {key}")
        if tool.get("status") == "detected" and not tool.get("version"):
            errors.append(f"detected tool missing version: {tool.get('tool')}")
        if tool.get("status") in {"skipped", "deferred"} and not tool.get("skipped_reason"):
            errors.append(f"skipped tool missing skipped_reason: {tool.get('tool')}")
        if tool.get("status") in {"degraded", "deferred"}:
            for key in ["os", "capability", "degradation", "degradation_reason"]:
                if not tool.get(key):
                    errors.append(f"{tool.get('status')} tool missing {key}: {tool.get('tool')}")
        for key in ["os", "capability", "availability", "provenance_class"]:
            if key not in tool:
                errors.append(f"TOOL_STATUS.json tools[{index}] missing {key}")


def validate_progress(path: Path, errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"missing required artifact: {path}")
        return
    text = path.read_text(encoding="utf-8")
    if "Current phase: 0 Bootstrap Sicuro" not in text:
        errors.append("PROGRESS.md missing current phase 0")
    for number, name in PHASES:
        expected = f"| {number} | {name} | pending |"
        if expected not in text:
            errors.append(f"PROGRESS.md missing phase row: {number} {name}")


def validate_blocked_attempts(payload: dict[str, Any] | None, errors: list[str]) -> None:
    if payload is None:
        return
    if payload.get("schema_version") != "1.0":
        errors.append("BLOCKED_COMMANDS_ATTEMPTS.json schema_version must be 1.0")
    if not isinstance(payload.get("attempts"), list):
        errors.append("BLOCKED_COMMANDS_ATTEMPTS.json requires attempts array")


def validate_phase0(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    tool_status = load_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"], errors)
    blocked_attempts = load_json(audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"], errors)
    validate_progress(audit_dir / ARTIFACT_PATHS["PROGRESS"], errors)
    validate_blocked_attempts(blocked_attempts, errors)

    if tool_status is not None:
        validate_tool_status(tool_status, errors)

    config_snapshot = audit_dir / ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"]
    if not config_snapshot.exists():
        errors.append(f"missing required artifact: {config_snapshot}")
    elif run_config is not None:
        expected_hash = (run_config.get("provenance") or {}).get("config_snapshot_sha256")
        if expected_hash and sha256_file(config_snapshot) != expected_hash:
            errors.append("audit.config.yaml.snapshot sha256 mismatch")

    if run_config is not None:
        network_snapshot_path = (run_config.get("provenance") or {}).get("network_policy_snapshot_path")
        if network_snapshot_path and not (audit_dir / str(network_snapshot_path)).exists():
            errors.append("network policy snapshot declared but missing")
        if tool_status is not None and not network_snapshot_path:
            network_record = next((tool for tool in tool_status.get("tools", []) if isinstance(tool, dict) and tool.get("tool") == "network_policy"), None)
            if not network_record or network_record.get("status") != "skipped":
                errors.append("missing network policy must be recorded as skipped")

    return ValidationResult(ok=not errors, errors=errors)


def validate_inventory_artifacts(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"], errors)
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
    inventory_path = audit_dir / ARTIFACT_PATHS["INVENTORY"]
    if not inventory_path.exists():
        errors.append(f"missing required artifact: {inventory_path}")
    if file_index is None:
        return ValidationResult(ok=False, errors=errors)
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or "."))
    records = file_index.get("records")
    if not isinstance(records, list):
        errors.append("FILE_INDEX.json requires records array")
        records = []
    seen_paths: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"FILE_INDEX.json records[{index}] must be object")
            continue
        path = str(record.get("path") or "")
        kind = record.get("kind")
        seen_paths.add(path)
        for key in ["path", "path_normalized", "size_bytes", "sha256", "extension", "kind", "binary"]:
            if key not in record:
                errors.append(f"FILE_INDEX.json record {path or index} missing {key}")
        if kind not in KIND_VALUES:
            errors.append(f"invalid file kind for {path}: {kind}")
        actual = repo_path / path
        if not actual.exists():
            errors.append(f"indexed file missing from repo: {path}")
        elif record.get("sha256") and sha256_file(actual) != record["sha256"]:
            errors.append(f"sha256 mismatch for indexed file: {path}")
    if evidence_index is not None:
        evidence_paths = {str(item.get("path")) for item in evidence_index.get("evidence", []) if isinstance(item, dict)}
        for doc in file_index.get("root_documents", []):
            if isinstance(doc, dict) and doc.get("status") == "found" and doc.get("path") not in evidence_paths:
                errors.append(f"root doc lacks evidence record: {doc.get('path')}")
    if inventory_path.exists():
        text = inventory_path.read_text(encoding="utf-8")
        for kind in KIND_VALUES:
            if f"| {kind} |" not in text:
                errors.append(f"INVENTORY.md missing kind count: {kind}")
    return ValidationResult(ok=not errors, errors=errors)


def validate_evidence_index_artifact(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
    if evidence_index is None:
        return ValidationResult(ok=False, errors=errors)
    repo_path = Path(str((evidence_index.get("repo") or {}).get("path") or "."))
    evidence_items = evidence_index.get("evidence")
    if not isinstance(evidence_items, list):
        errors.append("EVIDENCE_INDEX.json requires evidence array")
        return ValidationResult(ok=False, errors=errors)
    seen: set[str] = set()
    for index, item in enumerate(evidence_items):
        if not isinstance(item, dict):
            errors.append(f"EVIDENCE_INDEX.json evidence[{index}] must be object")
            continue
        evidence_id = str(item.get("id") or "")
        if not re.fullmatch(r"ev-\d{6}", evidence_id):
            errors.append(f"EVIDENCE_INDEX.json invalid evidence id: {evidence_id or index}")
        if evidence_id in seen:
            errors.append(f"EVIDENCE_INDEX.json duplicate evidence id: {evidence_id}")
        seen.add(evidence_id)
        path_value = str(item.get("path") or "")
        if not is_safe_relative_evidence_path(path_value):
            errors.append(f"evidence {evidence_id} has unsafe source path: {path_value or '<empty>'}")
            continue
        source = resolve_evidence_source(repo_path, path_value)
        if source is None:
            errors.append(f"evidence {evidence_id} has unsafe source path: {path_value or '<empty>'}")
            continue
        if not source.exists():
            errors.append(f"evidence source path missing: {path_value}")
            continue
        data = source.read_bytes()
        kind = item.get("kind")
        range_required = kind in BYTE_RANGE_REQUIRED_KINDS or item.get("binary_safe") is True
        start = item.get("start_byte")
        end = item.get("end_byte")
        if range_required and (start is None or end is None):
            errors.append(f"evidence {evidence_id} requires start_byte and end_byte")
            continue
        if start is None or end is None:
            expected_hash = sha256_file(source)
        elif not isinstance(start, int) or not isinstance(end, int):
            errors.append(f"evidence {evidence_id} byte range must be integers")
            continue
        elif start < 0 or end < start or end > len(data):
            errors.append(f"evidence {evidence_id} byte range out of bounds for {path_value}")
            continue
        else:
            expected_hash = sha256_range(data, start, end)
        if item.get("sha256") != expected_hash:
            errors.append(f"evidence {evidence_id} sha256 mismatch for {path_value}")
        if kind == "file_line":
            if not isinstance(item.get("start_line"), int) or not isinstance(item.get("end_line"), int):
                errors.append(f"evidence {evidence_id} file_line requires integer line range")
        if bool(item.get("binary_safe")):
            if "start_line" in item or "end_line" in item:
                errors.append(f"binary-safe evidence {evidence_id} must not require line range")
    claims = evidence_index.get("claims")
    if isinstance(claims, list):
        errors.extend(validate_claims_reach_evidence([claim for claim in claims if isinstance(claim, dict)], evidence_index))
    elif claims is not None:
        errors.append("EVIDENCE_INDEX.json claims must be an array when present")
    errors.extend(validate_evidence_provenance_drift(audit_dir, evidence_index))
    return ValidationResult(ok=not errors, errors=errors)


def validate_manifest_artifacts(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"], errors)
    ci_map = load_json(audit_dir / ARTIFACT_PATHS["CI_MAP"], errors)
    build_test_map = audit_dir / ARTIFACT_PATHS["BUILD_TEST_MAP"]
    if not build_test_map.exists():
        errors.append(f"missing required artifact: {build_test_map}")
    else:
        text = build_test_map.read_text(encoding="utf-8")
        command_rows = [line for line in text.splitlines() if line.startswith("| ") and "`" in line]
        for row in command_rows:
            if "observed, not executed" not in row:
                errors.append("BUILD_TEST_MAP.md command row missing observed-only label")
        if command_rows and "target_repo_manifest_no_exec" not in text:
            errors.append("BUILD_TEST_MAP.md command rows must record target_repo_manifest_no_exec policy")
    if manifests is not None:
        for index, record in enumerate(manifests.get("records", [])):
            if not isinstance(record, dict):
                errors.append(f"MANIFESTS.json records[{index}] must be object")
                continue
            if not record.get("evidence_ids"):
                errors.append(f"MANIFESTS.json record {record.get('path') or index} missing evidence_ids")
            for command in record.get("scripts") or []:
                validate_observed_command(command, f"MANIFESTS.json record {record.get('path')}", errors)
    if ci_map is not None:
        for index, record in enumerate(ci_map.get("records", [])):
            if not isinstance(record, dict):
                errors.append(f"CI_MAP.json records[{index}] must be object")
                continue
            if not record.get("evidence_ids"):
                errors.append(f"CI_MAP.json record {record.get('path') or index} missing evidence_ids")
            for command in record.get("commands") or []:
                validate_observed_command(command, f"CI_MAP.json record {record.get('path')}", errors)
    return ValidationResult(ok=not errors, errors=errors)


def validate_graph_artifacts(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], errors)
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], errors)
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], errors)
    architecture = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    if module_graph is not None:
        if not isinstance(module_graph.get("nodes"), list):
            errors.append("MODULE_GRAPH.json requires nodes array")
        for index, edge in enumerate(module_graph.get("edges", [])):
            if not isinstance(edge, dict):
                errors.append(f"MODULE_GRAPH.json edges[{index}] must be object")
                continue
            for key in ["type", "weight", "conditional", "dynamic", "evidence_ids"]:
                if key not in edge:
                    errors.append(f"MODULE_GRAPH.json edge {index} missing {key}")
            if edge.get("conditional") is True and float(edge.get("weight", 0)) > 0.5:
                errors.append(f"conditional graph edge has non-conservative weight: {edge.get('source')} -> {edge.get('target')}")
        centrality = module_graph.get("centrality")
        if not isinstance(centrality, dict):
            errors.append("MODULE_GRAPH.json missing centrality object")
    if symbol_index is not None:
        for index, symbol in enumerate(symbol_index.get("symbols", [])):
            if not isinstance(symbol, dict):
                errors.append(f"SYMBOL_INDEX.json symbols[{index}] must be object")
                continue
            if not symbol.get("evidence_ids"):
                errors.append(f"SYMBOL_INDEX.json symbol missing evidence_ids: {symbol.get('symbol_id') or index}")
            span = symbol.get("span")
            if not isinstance(span, dict):
                errors.append(f"SYMBOL_INDEX.json symbol missing span: {symbol.get('symbol_id') or index}")
            else:
                for key in ["start_line", "end_line", "start_byte", "end_byte"]:
                    if not isinstance(span.get(key), int):
                        errors.append(f"SYMBOL_INDEX.json symbol span missing integer {key}: {symbol.get('symbol_id') or index}")
    call_graph = audit_dir / ARTIFACT_PATHS["CALL_GRAPH"]
    skipped = audit_dir / ARTIFACT_PATHS["CALL_GRAPH_SKIPPED"]
    if call_graph.exists():
        payload = load_json(call_graph, errors)
        if payload is not None and not isinstance(payload.get("edges"), list):
            errors.append("CALL_GRAPH.json requires edges array")
    elif skipped.exists():
        if "Reason:" not in skipped.read_text(encoding="utf-8"):
            errors.append("CALL_GRAPH_SKIPPED.md missing reason")
    else:
        errors.append("graph phase requires CALL_GRAPH.json or CALL_GRAPH_SKIPPED.md")
    if not architecture.exists():
        errors.append(f"missing required artifact: {architecture}")
    elif "## Baseline" not in architecture.read_text(encoding="utf-8"):
        errors.append("ARCHITECTURE.md missing baseline section")
    if run_config is not None:
        graph = run_config.get("graph") if isinstance(run_config.get("graph"), dict) else {}
        centrality = graph.get("centrality") if isinstance(graph.get("centrality"), dict) else {}
        if centrality.get("algorithm", "weighted_in_degree") == "weighted_in_degree" and centrality.get("tie_break") != ["size_bytes_desc", "path_normalized_asc"]:
            errors.append("RUN_CONFIG.json graph.centrality missing required tie_break")
    return ValidationResult(ok=not errors, errors=errors)


def validate_surface_artifacts(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    artifacts = [
        ("API_SURFACE", ARTIFACT_PATHS["API_SURFACE"]),
        ("CLI_SURFACE", ARTIFACT_PATHS["CLI_SURFACE"]),
        ("MCP_SURFACE", ARTIFACT_PATHS["MCP_SURFACE"]),
        ("CONFIG_SURFACE", ARTIFACT_PATHS["CONFIG_SURFACE"]),
    ]
    for artifact_key, artifact_path in artifacts:
        payload = load_json(audit_dir / artifact_path, errors)
        if payload is None:
            continue
        records = payload.get("records")
        if not isinstance(records, list):
            errors.append(f"{artifact_path} requires records array")
            continue
        for index, record in enumerate(records):
            validate_surface_record(artifact_path, index, record, errors)
        if artifact_key == "CLI_SURFACE":
            for record in records:
                if isinstance(record, dict) and record.get("executable") is not False:
                    errors.append("CLI_SURFACE.json records must be observed, not executable")
        if artifact_key == "MCP_SURFACE":
            for record in records:
                if isinstance(record, dict) and record.get("host_imported") is not False:
                    errors.append("MCP_SURFACE.json target config must not be imported into host config")
        if artifact_key == "CONFIG_SURFACE":
            for record in records:
                if isinstance(record, dict) and record.get("kind") == "env_var" and ("value" in record or record.get("value_read") is not False):
                    errors.append("CONFIG_SURFACE.json env vars may record names only; values must not be read")
    return ValidationResult(ok=not errors, errors=errors)


def validate_surface_record(artifact_path: str, index: int, record: Any, errors: list[str]) -> None:
    if not isinstance(record, dict):
        errors.append(f"{artifact_path} records[{index}] must be object")
        return
    for key in ["surface_id", "kind", "source_path", "status", "evidence_ids", "sanitizer_decision"]:
        if key not in record:
            errors.append(f"{artifact_path} records[{index}] missing {key}")
    if record.get("status") not in {"observed", "heuristic", "skipped"}:
        errors.append(f"{artifact_path} records[{index}] invalid surface status: {record.get('status')}")
    if record.get("status") != "skipped" and not record.get("evidence_ids"):
        errors.append(f"{artifact_path} records[{index}] missing evidence_ids")
    source_path = str(record.get("source_path") or "")
    if Path(source_path).suffix.lower() in {".md", ".markdown", ".rst", ".txt", ".adoc"}:
        if record.get("sanitizer_decision") not in {"pass", "quoted_with_flags", "blocked_from_llm_context"}:
            errors.append(f"{artifact_path} records[{index}] Markdown-derived surface lacks sanitizer decision")
    elif record.get("sanitizer_decision") in {None, "", "unsanitized"}:
        errors.append(f"{artifact_path} records[{index}] invalid sanitizer decision")
    if record.get("status") == "observed" and record.get("confidence") == "low":
        errors.append(f"{artifact_path} records[{index}] low-confidence heuristic cannot be observed")


def validate_observed_command(command: Any, location: str, errors: list[str]) -> None:
    if not isinstance(command, dict):
        errors.append(f"{location} command must be object")
        return
    if command.get("label") != "observed, not executed":
        errors.append(f"{location} command missing observed-only label")
    if command.get("origin") != "target_repo_manifest":
        errors.append(f"{location} command origin must be target_repo_manifest")
    if command.get("policy_decision") != "block" or command.get("policy_rule") != "target_repo_manifest_no_exec":
        errors.append(f"{location} command must be blocked by target_repo_manifest_no_exec")


def validate_audit(audit_dir: Path) -> ValidationResult:
    phase0 = validate_phase0(audit_dir)
    errors = list(phase0.errors)
    if audit_dir.exists():
        errors.extend(validate_json_artifact_schemas(audit_dir))
    if (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).exists():
        phase1 = validate_inventory_artifacts(audit_dir)
        errors.extend(phase1.errors)
    if (audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).exists():
        evidence = validate_evidence_index_artifact(audit_dir)
        errors.extend(evidence.errors)
        evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
        if evidence_index is not None:
            errors.extend(validate_cross_artifact_evidence_references(audit_dir, evidence_index))
    if (audit_dir / ARTIFACT_PATHS["PROVENANCE"]).exists():
        provenance = validate_provenance_artifact(audit_dir)
        errors.extend(provenance.errors)
    if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() or (audit_dir / ARTIFACT_PATHS["CI_MAP"]).exists():
        manifests = validate_manifest_artifacts(audit_dir)
        errors.extend(manifests.errors)
    if (audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).exists() or (audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]).exists():
        graph = validate_graph_artifacts(audit_dir)
        errors.extend(graph.errors)
    if any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["API_SURFACE", "CLI_SURFACE", "MCP_SURFACE", "CONFIG_SURFACE"]):
        surfaces = validate_surface_artifacts(audit_dir)
        errors.extend(surfaces.errors)
    if any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["FEATURE_CATALOG", "PATTERNS", "SPECIAL_IMPLEMENTATIONS"]):
        evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
        if evidence_index is not None:
            synthesis = validate_synthesis_artifacts(audit_dir, evidence_index)
            errors.extend(synthesis.errors)
    if extension_artifacts_present(audit_dir):
        evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
        if evidence_index is not None:
            try:
                errors.extend(validate_extension_artifacts(audit_dir, evidence_index))
            except Exception as exc:  # noqa: BLE001 - validation must report blockers, not crash.
                errors.append(f"validation_exception: {type(exc).__name__}: {exc}")
    errors.extend(validate_anti_overclaim_language(audit_dir))
    return ValidationResult(ok=not errors, errors=errors)
