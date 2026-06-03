"""Validation helpers for audit output artifacts."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .audit_evidence import sha256_range, validate_claims_reach_evidence
from .audit_validate_common import ValidationResult, load_json
from .audit_validate_evidence import (
    validate_cross_artifact_evidence_references,
    validate_evidence_provenance_drift,
    validate_provenance_artifact,
    validate_synthesis_artifacts,
)
from .validate_claim_language import validate_anti_overclaim_language
from .validate_json_schema import validate_json_artifact_schemas
from .bootstrap import PHASES
from .config import sha256_file
from .limits import FileSizeLimitError, is_safe_repo_relative_path, read_bytes_capped, read_text_auto_capped, resolve_repo_file, sha256_file_capped
from .audit_inventory import KIND_VALUES
from .models import ARTIFACT_PATHS
from .validate_extensions import extension_artifacts_present, validate_extension_artifacts


BYTE_RANGE_REQUIRED_KINDS = {"file_line", "file_range", "symbol_span", "file_range_binary_safe"}
COMPLETE_PHASE_STATUSES = {"complete", "completed", "done", "ok", "pass", "passed"}
PHASE_REQUIRED_ARTIFACT_KEYS: dict[int, list[str]] = {
    0: ["RUN_CONFIG", "TOOL_STATUS", "PROGRESS", "BLOCKED_COMMANDS_ATTEMPTS"],
    1: ["FILE_INDEX", "INVENTORY", "EVIDENCE_INDEX", "PROVENANCE"],
    2: ["MANIFESTS", "BUILD_TEST_MAP", "CI_MAP"],
    3: ["MODULE_GRAPH", "SYMBOL_INDEX", "ARCHITECTURE"],
    4: ["API_SURFACE", "CLI_SURFACE", "MCP_SURFACE", "CONFIG_SURFACE"],
    5: ["FEATURE_CATALOG", "PATTERNS", "SPECIAL_IMPLEMENTATIONS"],
    6: ["RISK_FINDINGS", "RISK_REPORT", "LICENSE_CARDS", "LICENSE_MATRIX", "BINARY_ARTIFACTS"],
    7: ["PERFORMANCE_REVIEW", "QUALITY_REVIEW", "TEST_COVERAGE_SIGNAL", "AUDIT_RUNTIME_METRICS", "REUSE_CARDS", "REUSE_MAP"],
    8: ["WIKI_HOME", "WIKI_REPO_SUMMARY", "WIKI_ARCHITECTURE", "WIKI_REUSE_INDEX", "WIKI_RISK_INDEX", "GRAPH", "GRAPH_NODES", "GRAPH_EDGES", "CORPUS_INDEX"],
    9: ["VALIDATION_REPORT", "VALIDATION_REPORT_JSON", "REPORT", "OPEN_QUESTIONS", "REVIEW_LEDGER", "ADVERSARIAL_REVIEW_PACKET"],
}


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


def read_validation_text(path: Path, errors: list[str], label: str) -> str | None:
    if path.is_symlink():
        errors.append(f"{label}: symlink artifacts are not allowed: {path}")
        return None
    try:
        return read_text_auto_capped(path, encoding="utf-8", errors="replace", label=label)
    except FileSizeLimitError as exc:
        errors.append(f"{label}: {exc}")
        return None


def validate_progress(path: Path, errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"missing required artifact: {path}")
        return
    text = read_validation_text(path, errors, "PROGRESS.md")
    if text is None:
        return
    if "Current phase: 0 Bootstrap Sicuro" not in text:
        errors.append("PROGRESS.md missing current phase 0")
    for number, name in PHASES:
        expected = f"| {number} | {name} | pending |"
        if expected not in text:
            errors.append(f"PROGRESS.md missing phase row: {number} {name}")


def progress_phase_statuses(audit_dir: Path) -> dict[int, str]:
    path = audit_dir / ARTIFACT_PATHS["PROGRESS"]
    if not path.exists():
        return {}
    errors: list[str] = []
    text = read_validation_text(path, errors, "PROGRESS.md")
    if text is None:
        return {}
    statuses: dict[int, str] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip(" `") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 3 or not cells[0].isdigit():
            continue
        statuses[int(cells[0])] = cells[2].strip().casefold()
    return statuses


def validate_declared_phase_artifacts(audit_dir: Path, errors: list[str]) -> None:
    statuses = progress_phase_statuses(audit_dir)
    phase_names = dict(PHASES)
    for number, _name in PHASES:
        status = statuses.get(number, "")
        if status not in COMPLETE_PHASE_STATUSES:
            continue
        for key in PHASE_REQUIRED_ARTIFACT_KEYS.get(number, []):
            artifact_path = audit_dir / ARTIFACT_PATHS[key]
            if not artifact_path.exists():
                errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS[key]}")
        if number == 3 and not (audit_dir / ARTIFACT_PATHS["CALL_GRAPH"]).exists() and not (audit_dir / ARTIFACT_PATHS["CALL_GRAPH_SKIPPED"]).exists():
            errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS['CALL_GRAPH']} or {ARTIFACT_PATHS['CALL_GRAPH_SKIPPED']}")
        if number == 6 and not (audit_dir / ARTIFACT_PATHS["SBOM"]).exists() and not (audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]).exists():
            errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS['SBOM']} or {ARTIFACT_PATHS['SBOM_SKIPPED']}")
        if number == 8:
            if not (audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]).exists() and not (audit_dir / ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"]).exists():
                errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS['GRAPH_HTML']} or {ARTIFACT_PATHS['GRAPH_HTML_SKIPPED']}")
            if not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists() and not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]).exists():
                errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS['GRAPHIFY_GRAPH']} or {ARTIFACT_PATHS['GRAPHIFY_SKIPPED']}")
            if not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE"]).exists() and not (audit_dir / ARTIFACT_PATHS["CORPUS_SQLITE_SKIPPED"]).exists():
                errors.append(f"phase {number} {phase_names[number]} declared {status} but missing artifact: {ARTIFACT_PATHS['CORPUS_SQLITE']} or {ARTIFACT_PATHS['CORPUS_SQLITE_SKIPPED']}")
            if not any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"]):
                errors.append(f"phase {number} {phase_names[number]} declared {status} but missing MCP handoff artifact")


def validate_blocked_attempts(payload: dict[str, Any] | None, errors: list[str]) -> None:
    if payload is None:
        return
    if payload.get("schema_version") != "1.0":
        errors.append("BLOCKED_COMMANDS_ATTEMPTS.json schema_version must be 1.0")
    if not isinstance(payload.get("attempts"), list):
        errors.append("BLOCKED_COMMANDS_ATTEMPTS.json requires attempts array")


def run_config_repo_path(audit_dir: Path) -> Path | None:
    path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    if not path.exists():
        return None
    try:
        payload = json.loads(read_text_auto_capped(path, encoding="utf-8", label="RUN_CONFIG.json"))
    except (FileSizeLimitError, json.JSONDecodeError):
        return None
    repo = payload.get("repo") if isinstance(payload, dict) else {}
    repo_path = repo.get("path") if isinstance(repo, dict) else None
    if not isinstance(repo_path, str) or not repo_path:
        return None
    return Path(repo_path).resolve()


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
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or ".")).resolve()
    expected_repo_path = run_config_repo_path(audit_dir)
    if expected_repo_path is not None and repo_path != expected_repo_path:
        errors.append("FILE_INDEX.json repo.path differs from RUN_CONFIG.json repo.path")
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
        if not is_safe_repo_relative_path(path):
            errors.append(f"FILE_INDEX.json record has unsafe source path: {path or '<empty>'}")
            continue
        actual = resolve_repo_file(repo_path, path)
        if actual is None:
            errors.append(f"FILE_INDEX.json record has unsafe source path: {path or '<empty>'}")
            continue
        if not actual.exists():
            errors.append(f"indexed file missing from repo: {path}")
        elif record.get("sha256"):
            try:
                actual_hash = sha256_file_capped(actual, label="indexed file")
            except FileSizeLimitError as exc:
                errors.append(f"indexed file exceeds validation size cap: {path}: {exc}")
                continue
            if actual_hash != record["sha256"]:
                errors.append(f"sha256 mismatch for indexed file: {path}")
    if evidence_index is not None:
        evidence_paths = {str(item.get("path")) for item in evidence_index.get("evidence", []) if isinstance(item, dict)}
        for doc in file_index.get("root_documents", []):
            if isinstance(doc, dict) and doc.get("status") == "found" and doc.get("path") not in evidence_paths:
                errors.append(f"root doc lacks evidence record: {doc.get('path')}")
    if inventory_path.exists():
        text = read_validation_text(inventory_path, errors, "INVENTORY.md")
        if text is not None:
            for kind in KIND_VALUES:
                if f"| {kind} |" not in text:
                    errors.append(f"INVENTORY.md missing kind count: {kind}")
    return ValidationResult(ok=not errors, errors=errors)


def validate_evidence_index_artifact(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
    if evidence_index is None:
        return ValidationResult(ok=False, errors=errors)
    evidence_items = evidence_index.get("evidence")
    if not isinstance(evidence_items, list):
        errors.append("EVIDENCE_INDEX.json requires evidence array")
        return ValidationResult(ok=False, errors=errors)
    repo_path = Path(str((evidence_index.get("repo") or {}).get("path") or ".")).resolve()
    expected_repo_path = run_config_repo_path(audit_dir)
    if expected_repo_path is not None and repo_path != expected_repo_path:
        errors.append("EVIDENCE_INDEX.json repo.path differs from RUN_CONFIG.json repo.path")
    seen: set[str] = set()
    for index, item in enumerate(evidence_items):
        if not isinstance(item, dict):
            errors.append(f"EVIDENCE_INDEX.json evidence[{index}] must be object")
            continue
        evidence_id = str(item.get("id") or "")
        if not re.fullmatch(r"ev-\d{6,}", evidence_id):
            errors.append(f"EVIDENCE_INDEX.json invalid evidence id: {evidence_id or index}")
        if evidence_id in seen:
            errors.append(f"EVIDENCE_INDEX.json duplicate evidence id: {evidence_id}")
        seen.add(evidence_id)
        path_value = str(item.get("path") or "")
        if not is_safe_repo_relative_path(path_value):
            errors.append(f"evidence {evidence_id} has unsafe source path: {path_value or '<empty>'}")
            continue
        source = resolve_repo_file(repo_path, path_value)
        if source is None:
            errors.append(f"evidence {evidence_id} has unsafe source path: {path_value or '<empty>'}")
            continue
        if not source.exists():
            errors.append(f"evidence source path missing: {path_value}")
            continue
        try:
            data = read_bytes_capped(source, label="evidence validation source")
        except FileSizeLimitError as exc:
            errors.append(f"evidence source exceeds validation size cap: {path_value}: {exc}")
            continue
        kind = item.get("kind")
        range_required = kind in BYTE_RANGE_REQUIRED_KINDS or item.get("binary_safe") is True
        start = item.get("start_byte")
        end = item.get("end_byte")
        if (start is not None or end is not None) and item.get("byte_basis") not in {None, "raw_file_bytes"}:
            errors.append(f"evidence {evidence_id} byte_basis must be raw_file_bytes")
        if range_required and (start is None or end is None):
            errors.append(f"evidence {evidence_id} requires start_byte and end_byte")
            continue
        if start is None or end is None:
            expected_hash = sha256_range(data, 0, len(data))
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
        text = read_validation_text(build_test_map, errors, "BUILD_TEST_MAP.md")
        if text is not None:
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
            edge_weight = edge.get("weight")
            if (isinstance(edge_weight, bool) or not isinstance(edge_weight, (int, float))
                    or not math.isfinite(edge_weight) or edge_weight < 0):
                errors.append(f"MODULE_GRAPH.json edge {index} weight must be a finite non-negative number")
        # FIX-GRAPHVAL (2026-06-03): replaced the per-edge "conditional weight > 0.5" cap with the finite
        # non-negative weight guard above (swarm review). The conservatism of
        # conditional import edges is enforced by the per-site DISCOUNT (conditional_import_weight <
        # normal_import_weight), NOT by an absolute cap on the SUMMED weight. B03 deliberately accumulates the
        # per-site 0.5 weights across distinct import sites so centrality reflects import frequency
        # (test_b03_distinct_import_sites_accumulate_weight), so a module imported conditionally N times
        # legitimately reaches weight 0.5*N (>0.5 for N>=2). The old cap also hardcoded 0.5 while the per-site
        # weight is configurable (e.g. 0.25). It false-blocked REPORT.md on real repos with repeated
        # try/except provider imports (hermes-agent: 178 conditional edges, all legitimate 0.5-multiples).
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
        skipped_text = read_validation_text(skipped, errors, "CALL_GRAPH_SKIPPED.md")
        if skipped_text is not None and "Reason:" not in skipped_text:
            errors.append("CALL_GRAPH_SKIPPED.md missing reason")
    else:
        errors.append("graph phase requires CALL_GRAPH.json or CALL_GRAPH_SKIPPED.md")
    if not architecture.exists():
        errors.append(f"missing required artifact: {architecture}")
    else:
        architecture_text = read_validation_text(architecture, errors, "ARCHITECTURE.md")
        if architecture_text is not None and "## Baseline" not in architecture_text:
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


def _parse_schema_version_tuple(value: str) -> tuple[int, ...] | None:
    """Parse a dot-separated numeric schema_version into a tuple; None if non-empty malformed."""
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return None


def validate_run_config_launch_surface(audit_dir: Path, errors: list[str], warnings: list[str]) -> None:
    """Enforce launch_surface semantics on RUN_CONFIG.json via numeric-tuple schema_version.

    Missing or < (1,1) schema_version is legacy and emits a [LEGACY] warning; schema_version
    >= (1,1) with no launch_surface is a blocker; a malformed non-empty schema_version is a blocker.
    The JSON Schema only defines the launch_surface shape; presence logic lives here (004).
    """
    path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    if not path.exists():
        return
    run_config = load_json(path, errors)
    if run_config is None:
        return
    raw_version = run_config.get("schema_version")
    if raw_version is None:
        version_tuple: tuple[int, ...] = (0,)
    else:
        parsed = _parse_schema_version_tuple(str(raw_version))
        if parsed is None:
            errors.append("RUN_CONFIG.json schema_version malformed")
            return
        version_tuple = parsed
    if version_tuple < (1, 1):
        timestamp = run_config.get("run_id") or "unknown"
        launch_surface = run_config.get("launch_surface")
        inferred = launch_surface.get("adapter") if isinstance(launch_surface, dict) else "cli"
        warnings.append(
            f"[LEGACY] RUN_CONFIG.json predates launch_surface schema (run timestamp {timestamp}); "
            f"validation proceeded with best-effort adapter inference: {inferred}."
        )
    elif "launch_surface" not in run_config:
        errors.append("RUN_CONFIG.json schema_version >= 1.1 requires launch_surface")


def validate_audit(audit_dir: Path) -> ValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    def _guard(label: str, run) -> None:
        # OQ-M11: a phase validator raising (e.g. on a malformed artifact) must be recorded as a
        # blocker, never abort the whole validation run. Mirrors the extension/review-packet guards.
        try:
            run()
        except Exception as exc:  # noqa: BLE001 - validation surfaces blockers; it does not crash.
            errors.append(f"validation_exception: {label}: {type(exc).__name__}: {exc}")

    _guard("phase0", lambda: errors.extend(validate_phase0(audit_dir).errors))
    _guard("run_config_launch_surface", lambda: validate_run_config_launch_surface(audit_dir, errors, warnings))
    _guard("declared_phase_artifacts", lambda: validate_declared_phase_artifacts(audit_dir, errors))
    if audit_dir.exists():
        _guard("json_schemas", lambda: errors.extend(validate_json_artifact_schemas(audit_dir)))
    if (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).exists():
        _guard("inventory", lambda: errors.extend(validate_inventory_artifacts(audit_dir).errors))
    if (audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).exists():
        def _evidence() -> None:
            errors.extend(validate_evidence_index_artifact(audit_dir).errors)
            evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
            if evidence_index is not None:
                errors.extend(validate_cross_artifact_evidence_references(audit_dir, evidence_index))
        _guard("evidence_index", _evidence)
    if (audit_dir / ARTIFACT_PATHS["PROVENANCE"]).exists():
        _guard("provenance", lambda: errors.extend(validate_provenance_artifact(audit_dir).errors))
    if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() or (audit_dir / ARTIFACT_PATHS["CI_MAP"]).exists():
        _guard("manifests", lambda: errors.extend(validate_manifest_artifacts(audit_dir).errors))
    if (audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).exists() or (audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]).exists():
        _guard("graph", lambda: errors.extend(validate_graph_artifacts(audit_dir).errors))
    if any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["API_SURFACE", "CLI_SURFACE", "MCP_SURFACE", "CONFIG_SURFACE"]):
        _guard("surfaces", lambda: errors.extend(validate_surface_artifacts(audit_dir).errors))
    if any((audit_dir / ARTIFACT_PATHS[key]).exists() for key in ["FEATURE_CATALOG", "PATTERNS", "SPECIAL_IMPLEMENTATIONS"]):
        def _synthesis() -> None:
            evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
            if evidence_index is not None:
                errors.extend(validate_synthesis_artifacts(audit_dir, evidence_index).errors)
        _guard("synthesis", _synthesis)
    if extension_artifacts_present(audit_dir):
        evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], errors)
        if evidence_index is not None:
            try:
                errors.extend(validate_extension_artifacts(audit_dir, evidence_index))
            except Exception as exc:  # noqa: BLE001 - validation must report blockers, not crash.
                errors.append(f"validation_exception: {type(exc).__name__}: {exc}")
    try:
        from .validate_report_packet import validate_review_packet

        validate_review_packet(audit_dir, errors)
    except Exception as exc:  # noqa: BLE001 - report packet checks must fail as validation blockers.
        errors.append(f"validation_exception: {type(exc).__name__}: {exc}")
    _guard("anti_overclaim", lambda: errors.extend(validate_anti_overclaim_language(audit_dir)))
    return ValidationResult(ok=not errors, errors=errors, warnings=warnings)
