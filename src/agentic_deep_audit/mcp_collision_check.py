"""Host MCP metadata collision check with narrow read-only exception."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .mcp_policy import redact_value


GENERATED_SERVER_NAME = "agentic_deep_audit"
GENERATED_TOOL_NAMES = [
    "agentic_deep_audit_audit_query",
    "agentic_deep_audit_artifact_read",
    "agentic_deep_audit_graph_neighbors",
    "agentic_deep_audit_wiki_page",
]
DEFAULT_HOST_CONFIGS = [Path.home() / ".codex" / "mcp.json", Path.home() / ".claude" / "mcp.json"]


def expand_host_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value)))


def configured_host_paths(run_config: dict[str, Any]) -> list[Path]:
    mcp_config = run_config.get("mcp_config") if isinstance(run_config.get("mcp_config"), dict) else {}
    paths = mcp_config.get("host_config_paths")
    if paths is None:
        return DEFAULT_HOST_CONFIGS
    if not isinstance(paths, list):
        return []
    return [expand_host_path(str(path)) for path in paths if str(path).strip()]


def safe_text(value: Any) -> str:
    return str(redact_value(str(value)))


def safe_path_text(path: Path) -> str:
    return safe_text(path.resolve(strict=False))


def raw_names_from_collection(value: Any) -> list[str]:
    names: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            names.append(str(key))
            if isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
    return sorted(set(names))


def safe_names(values: list[str]) -> list[str]:
    return sorted({safe_text(value) for value in values})


def extract_server_metadata(path: Path, payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    servers = payload.get("mcpServers") if isinstance(payload.get("mcpServers"), dict) else payload.get("servers")
    if not isinstance(servers, dict):
        return [], []
    metadata: list[dict[str, Any]] = []
    collisions: list[dict[str, str]] = []
    generated = set(GENERATED_TOOL_NAMES)
    for server_name, server_payload in servers.items():
        server = server_payload if isinstance(server_payload, dict) else {}
        raw_tool_names = raw_names_from_collection(server.get("tools"))
        raw_resource_names = raw_names_from_collection(server.get("resources"))
        raw_prompt_names = raw_names_from_collection(server.get("prompts"))
        for tool_name in raw_tool_names:
            if tool_name in generated or tool_name.startswith("agentic_deep_audit_"):
                collisions.append({"server_name": safe_text(server_name), "tool_name": safe_text(tool_name), "host_path": safe_path_text(path)})
        metadata.append(
            {
                "host_path": safe_path_text(path),
                "server_name": safe_text(server_name),
                "tool_names": safe_names(raw_tool_names),
                "resource_names": safe_names(raw_resource_names),
                "prompt_names": safe_names(raw_prompt_names),
                "arg_count": len(server.get("args", [])) if isinstance(server.get("args"), list) else 0,
            }
        )
    return metadata, collisions


def read_host_mcp_state(run_config: dict[str, Any]) -> dict[str, Any]:
    paths = configured_host_paths(run_config)
    if not paths:
        return {"state": "unknown", "reason": "mcp_config.host_config_paths is missing or invalid", "hosts": [], "collisions": []}
    hosts: list[dict[str, Any]] = []
    collisions: list[dict[str, str]] = []
    for path in paths:
        if not path.exists():
            return {"state": "unknown", "reason": f"host MCP config not readable: {safe_path_text(path)}", "hosts": hosts, "collisions": []}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"state": "unknown", "reason": f"host MCP config parse failed: {safe_path_text(path)}: {type(exc).__name__}", "hosts": hosts, "collisions": []}
        if not isinstance(payload, dict):
            return {"state": "unknown", "reason": f"host MCP config root is not object: {safe_path_text(path)}", "hosts": hosts, "collisions": []}
        host_metadata, host_collisions = extract_server_metadata(path, payload)
        hosts.extend(host_metadata)
        collisions.extend(host_collisions)
    if collisions:
        return {"state": "collision", "reason": "host MCP tool name collision", "hosts": hosts, "collisions": collisions}
    return {"state": "clear", "reason": "host MCP metadata checked", "hosts": hosts, "collisions": []}
