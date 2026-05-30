"""Validation for generated MCP export artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, read_json_capped, read_text_auto_capped
from .mcp_collision_check import GENERATED_SERVER_NAME, GENERATED_TOOL_NAMES
from .mcp_policy import looks_secret
from .models import ARTIFACT_PATHS, load_schema_registry


MCP_KEYS = ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"]
MAX_MCP_STRING_WALK_DEPTH = 256


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        payload = read_json_capped(path, label="mcp validation JSON")
    except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
        errors.append(f"invalid MCP JSON artifact: {path}: {exc}")
        return {}
    if not isinstance(payload, dict):
        errors.append(f"invalid MCP JSON artifact: {path}: root must be object")
        return {}
    return payload


def collect_strings(value: Any) -> list[str]:
    result: list[str] = []
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > MAX_MCP_STRING_WALK_DEPTH:
            continue
        if isinstance(current, dict):
            for key, item in current.items():
                result.append(str(key))
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))
        elif isinstance(current, str):
            result.append(current)
    return result


def artifact_set(audit_dir: Path) -> list[str]:
    return [key for key in MCP_KEYS if (audit_dir / ARTIFACT_PATHS[key]).exists()]


def run_requires_mcp_output(audit_dir: Path, errors: list[str]) -> bool:
    run_config_path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    if not run_config_path.exists():
        return False
    run_config = load_json(run_config_path, errors)
    return run_config.get("command") == "run"


def validate_mcp_config(audit_dir: Path, errors: list[str]) -> None:
    payload = load_json(audit_dir / ARTIFACT_PATHS["MCP_CONFIG"], errors)
    if not payload:
        return
    from jsonschema import Draft202012Validator

    schema = load_schema_registry()["mcp_config"].schema
    for error in sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path)):
        location = ".".join(str(part) for part in error.path) or "<root>"
        errors.append(f"mcp_config_schema: {location}: {error.message}")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict) or GENERATED_SERVER_NAME not in servers:
        errors.append("mcp/.mcp.json requires generated agentic_deep_audit server")
        return
    if set(servers) != {GENERATED_SERVER_NAME}:
        errors.append("mcp/.mcp.json must contain only the generated agentic_deep_audit server")
    server = servers[GENERATED_SERVER_NAME]
    if not isinstance(server, dict):
        errors.append("mcp/.mcp.json generated server must be object")
        return
    if server.get("read_only") is not True:
        errors.append("mcp/.mcp.json generated server must be read_only")
    if server.get("command") != "python":
        errors.append("mcp/.mcp.json generated server command must be python")
    expected_args = ["-m", "agentic_deep_audit.mcp_readonly_server", "--audit-dir", "${AGENTIC_DEEP_AUDIT_AUDIT_DIR}"]
    if server.get("args") != expected_args:
        errors.append("mcp/.mcp.json generated server args must match read-only server invocation")
    if server.get("env") != {"AGENTIC_DEEP_AUDIT_AUDIT_DIR": "${AGENTIC_DEEP_AUDIT_AUDIT_DIR}"}:
        errors.append("mcp/.mcp.json generated server env must contain only AGENTIC_DEEP_AUDIT_AUDIT_DIR token")
    tools = server.get("tools") if isinstance(server.get("tools"), list) else []
    raw_tool_names = [tool.get("name") for tool in tools if isinstance(tool, dict)]
    tool_names = set(raw_tool_names)
    if len(raw_tool_names) != len(tool_names):
        errors.append("mcp/.mcp.json generated tools must not contain duplicates")
    if set(GENERATED_TOOL_NAMES) - tool_names:
        errors.append("mcp/.mcp.json missing generated prefixed tool names")
    if tool_names - set(GENERATED_TOOL_NAMES):
        errors.append("mcp/.mcp.json contains unexpected generated tool names")
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            errors.append(f"mcp/.mcp.json tools[{index}] must be object")
            continue
        if tool.get("read_only") is not True:
            errors.append(f"mcp/.mcp.json tool {tool.get('name')} must be read_only")
    for name in tool_names:
        if not isinstance(name, str) or not name.startswith("agentic_deep_audit_"):
            errors.append(f"mcp/.mcp.json has unprefixed tool name: {name}")
    resources = server.get("resources") if isinstance(server.get("resources"), list) else []
    resource_names = {resource.get("name") for resource in resources if isinstance(resource, dict)}
    expected_resources = {"agentic_deep_audit_corpus", "agentic_deep_audit_graph", "agentic_deep_audit_wiki_home"}
    if resource_names != expected_resources:
        errors.append("mcp/.mcp.json resources must match generated read-only audit resources")
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            errors.append(f"mcp/.mcp.json resources[{index}] must be object")
            continue
        if resource.get("read_only") is not True:
            errors.append(f"mcp/.mcp.json resource {resource.get('name')} must be read_only")
        path_value = resource.get("path")
        if not isinstance(path_value, str) or path_value.startswith("/") or "\\" in path_value or ":" in path_value or ".." in Path(path_value).parts:
            errors.append(f"mcp/.mcp.json resource {resource.get('name')} path must be audit-relative")
    for value in collect_strings(payload):
        if looks_secret(value):
            errors.append("mcp/.mcp.json contains secret-like string")
        if value.endswith(".mcp.json") and value != ARTIFACT_PATHS["MCP_CONFIG"]:
            errors.append("mcp/.mcp.json must not reference target or host MCP config paths")
        if "\\" in value or value.startswith("/") or (len(value) > 2 and value[1:3] == ":\\"):
            if value != "${AGENTIC_DEEP_AUDIT_AUDIT_DIR}":
                errors.append("mcp/.mcp.json contains raw filesystem path instead of audit-relative path/env token")


def validate_mcp_tool_status(audit_dir: Path, expected_status: str, expected_output_path: str, errors: list[str]) -> None:
    status_path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    if not status_path.exists():
        errors.append("MCP export artifact requires TOOL_STATUS.json provenance")
        return
    status_payload = load_json(status_path, errors)
    records = status_payload.get("tools") if isinstance(status_payload.get("tools"), list) else []
    if not any(record.get("tool") == "mcp_export" and record.get("status") == expected_status and record.get("output_path") == expected_output_path for record in records if isinstance(record, dict)):
        errors.append(f"MCP export artifact requires mcp_export TOOL_STATUS status={expected_status} output_path={expected_output_path}")


def validate_mcp_report(path: Path, expected_titles: set[str], errors: list[str]) -> None:
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="mcp report")
    except (OSError, FileSizeLimitError) as exc:
        errors.append(f"{path.name} invalid artifact: {exc}")
        return
    first_line = text.splitlines()[0].strip() if text.splitlines() else ""
    if first_line not in expected_titles:
        errors.append(f"{path.name} missing expected MCP report header")
    if "Reason:" not in text:
        errors.append(f"{path.name} missing Reason")
    if looks_secret(text):
        errors.append(f"{path.name} contains secret-like string")
    for value in text.split():
        stripped = value.strip("`.,;:()[]{}")
        if looks_secret(stripped):
            errors.append(f"{path.name} contains secret-like string")


def validate_mcp_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    present = artifact_set(audit_dir)
    required = run_requires_mcp_output(audit_dir, errors)
    if not present and not required:
        return errors
    if not present and (audit_dir / ARTIFACT_PATHS["MCP_SURFACE"]).exists():
        errors.append("target MCP_SURFACE.json cannot satisfy generated MCP output requirement")
    if len(present) != 1:
        errors.append("mcp_artifact_set: exactly one of mcp/.mcp.json, MCP_DEFERRED.md, MCP_COLLISION_REPORT.md is required")
        return errors
    if present[0] == "MCP_CONFIG":
        validate_mcp_config(audit_dir, errors)
        validate_mcp_tool_status(audit_dir, "completed", ARTIFACT_PATHS["MCP_CONFIG"], errors)
    elif present[0] == "MCP_DEFERRED":
        validate_mcp_report(audit_dir / ARTIFACT_PATHS["MCP_DEFERRED"], {"# MCP Deferred"}, errors)
        validate_mcp_tool_status(audit_dir, "deferred", ARTIFACT_PATHS["MCP_DEFERRED"], errors)
    elif present[0] == "MCP_COLLISION_REPORT":
        validate_mcp_report(audit_dir / ARTIFACT_PATHS["MCP_COLLISION_REPORT"], {"# MCP Collision Report", "# MCP Blocked Report"}, errors)
        validate_mcp_tool_status(audit_dir, "blocked", ARTIFACT_PATHS["MCP_COLLISION_REPORT"], errors)
    return errors
