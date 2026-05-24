"""Validation for generated MCP export artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .mcp_collision_check import GENERATED_SERVER_NAME, GENERATED_TOOL_NAMES
from .mcp_policy import looks_secret
from .models import ARTIFACT_PATHS


MCP_KEYS = ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"]


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid MCP JSON artifact: {path}: {exc}")
        return {}
    return payload if isinstance(payload, dict) else {}


def collect_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        result: list[str] = []
        for key, item in value.items():
            result.append(str(key))
            result.extend(collect_strings(item))
        return result
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(collect_strings(item))
        return result
    return [value] if isinstance(value, str) else []


def artifact_set(audit_dir: Path) -> list[str]:
    return [key for key in MCP_KEYS if (audit_dir / ARTIFACT_PATHS[key]).exists()]


def run_requires_mcp_output(audit_dir: Path) -> bool:
    run_config = load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], [])
    return run_config.get("command") == "run" and (audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]).exists()


def validate_mcp_config(audit_dir: Path, errors: list[str]) -> None:
    payload = load_json(audit_dir / ARTIFACT_PATHS["MCP_CONFIG"], errors)
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict) or GENERATED_SERVER_NAME not in servers:
        errors.append("mcp/.mcp.json requires generated agentic_deep_audit server")
        return
    server = servers[GENERATED_SERVER_NAME]
    if not isinstance(server, dict):
        errors.append("mcp/.mcp.json generated server must be object")
        return
    if server.get("read_only") is not True:
        errors.append("mcp/.mcp.json generated server must be read_only")
    tools = server.get("tools") if isinstance(server.get("tools"), list) else []
    tool_names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if set(GENERATED_TOOL_NAMES) - tool_names:
        errors.append("mcp/.mcp.json missing generated prefixed tool names")
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


def validate_mcp_report(path: Path, errors: list[str]) -> None:
    text = path.read_text(encoding="utf-8")
    if "Reason:" not in text:
        errors.append(f"{path.name} missing Reason")
    for value in text.split():
        stripped = value.strip("`.,;:()[]{}")
        if looks_secret(stripped):
            errors.append(f"{path.name} contains secret-like string")


def validate_mcp_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    present = artifact_set(audit_dir)
    if not present and not run_requires_mcp_output(audit_dir):
        return errors
    if not present and (audit_dir / ARTIFACT_PATHS["MCP_SURFACE"]).exists():
        errors.append("target MCP_SURFACE.json cannot satisfy generated MCP output requirement")
    if len(present) != 1:
        errors.append("mcp_artifact_set: exactly one of mcp/.mcp.json, MCP_DEFERRED.md, MCP_COLLISION_REPORT.md is required")
        return errors
    if present[0] == "MCP_CONFIG":
        validate_mcp_config(audit_dir, errors)
    elif present[0] == "MCP_DEFERRED":
        validate_mcp_report(audit_dir / ARTIFACT_PATHS["MCP_DEFERRED"], errors)
    elif present[0] == "MCP_COLLISION_REPORT":
        validate_mcp_report(audit_dir / ARTIFACT_PATHS["MCP_COLLISION_REPORT"], errors)
    return errors
