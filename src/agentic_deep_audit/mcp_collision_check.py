"""Host MCP metadata collision check with narrow read-only exception."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, MAX_MANIFEST_FILE_BYTES, read_json_capped
from .mcp_policy import redact_value


GENERATED_SERVER_NAME = "agentic_deep_audit"
GENERATED_TOOL_NAMES = [
    "agentic_deep_audit_audit_query",
    "agentic_deep_audit_artifact_read",
    "agentic_deep_audit_graph_neighbors",
    "agentic_deep_audit_wiki_page",
]
GENERATED_NAME_PREFIX = "agentic_deep_audit_"
MAX_HOST_CONFIG_BYTES = 1024 * 1024
MAX_HOST_CONFIG_PATHS = 16
MAX_HOST_CONFIG_PATH_CHARS = 4096
DEFAULT_HOST_CONFIGS = [
    Path.home() / ".codex" / "mcp.json",
    Path.home() / ".claude" / "mcp.json",
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".continue" / "mcp.json",
    Path.home() / ".goose" / "mcp.json",
    Path.home() / ".zed" / "mcp.json",
    Path.home() / ".windsurf" / "mcp.json",
    Path.home() / ".antigravity" / "mcp.json",
    Path.home() / ".vscode" / "mcp.json",
    Path.home() / "AppData" / "Roaming" / "Code" / "User" / "mcp.json",
    Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
]
ALLOWED_HOST_CONFIG_NAME = re.compile(r"(?i).*(mcp|claude|cursor|continue|goose|zed|windsurf|antigravity|vscode|host).*\.json$")


def expand_host_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value)))


def configured_host_paths(run_config: dict[str, Any]) -> list[Path]:
    paths, _explicit = host_paths_from_config(run_config)
    return paths


def host_paths_from_config(run_config: dict[str, Any]) -> tuple[list[Path], bool]:
    mcp_config = run_config.get("mcp_config") if isinstance(run_config.get("mcp_config"), dict) else {}
    paths = mcp_config.get("host_config_paths")
    if paths is None:
        return DEFAULT_HOST_CONFIGS, False
    if not isinstance(paths, list) or len(paths) > MAX_HOST_CONFIG_PATHS:
        return [], True
    result: list[Path] = []
    for path in paths:
        if not isinstance(path, str) or not path.strip() or len(path) > MAX_HOST_CONFIG_PATH_CHARS:
            return [], True
        result.append(expand_host_path(path))
    return result, True


def safe_text(value: Any) -> str:
    return str(redact_value(str(value)))


def safe_path_text(path: Path) -> str:
    return safe_text(path.resolve(strict=False))


def symlink_component(path: Path) -> Path | None:
    current = path.anchor and Path(path.anchor) or Path()
    for part in path.parts if not path.is_absolute() else path.parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                return current
        except OSError:
            return current
    return None


def validate_host_config_path(path: Path) -> str | None:
    if not ALLOWED_HOST_CONFIG_NAME.fullmatch(path.name):
        return f"host MCP config path has unsupported filename: {safe_path_text(path)}"
    link = symlink_component(path)
    if link is not None:
        return f"host MCP config path uses symlink or reparse point: {safe_path_text(link)}"
    try:
        stat_result = path.stat()
    except OSError as exc:
        return f"host MCP config not readable: {safe_path_text(path)}: {type(exc).__name__}"
    if not path.is_file():
        return f"host MCP config path is not a file: {safe_path_text(path)}"
    if stat_result.st_size > MAX_HOST_CONFIG_BYTES:
        return f"host MCP config exceeds size cap: {safe_path_text(path)}"
    return None


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


def extract_server_metadata(path: Path, payload: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]], list[str]]:
    servers = payload.get("mcpServers") if isinstance(payload.get("mcpServers"), dict) else payload.get("servers")
    if not isinstance(servers, dict):
        return [], [], []
    metadata: list[dict[str, Any]] = []
    collisions: list[dict[str, str]] = []
    errors: list[str] = []
    generated = {name.lower() for name in GENERATED_TOOL_NAMES}
    for server_name, server_payload in sorted(servers.items(), key=lambda item: str(item[0])):
        server = server_payload if isinstance(server_payload, dict) else {}
        raw_tool_names = raw_names_from_collection(server.get("tools"))
        raw_resource_names = raw_names_from_collection(server.get("resources"))
        raw_prompt_names = raw_names_from_collection(server.get("prompts"))
        has_dynamic_transport = bool(server.get("command") or server.get("args") or server.get("url") or server.get("transport") or server.get("endpoint"))
        if has_dynamic_transport and not (raw_tool_names or raw_resource_names or raw_prompt_names):
            errors.append(f"host MCP server exposes dynamic metadata without static tools/resources/prompts: {safe_text(server_name)} from {safe_path_text(path)}")
        for collection_name, raw_names in [("tool", raw_tool_names), ("resource", raw_resource_names), ("prompt", raw_prompt_names)]:
            for name in raw_names:
                lowered = name.lower()
                if lowered in generated or lowered.startswith(GENERATED_NAME_PREFIX):
                    collisions.append({"server_name": safe_text(server_name), "kind": collection_name, "name": safe_text(name), "tool_name": safe_text(name), "host_path": safe_path_text(path)})
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
    return metadata, collisions, errors


def read_host_mcp_state(run_config: dict[str, Any]) -> dict[str, Any]:
    paths, explicit_paths = host_paths_from_config(run_config)
    if not paths:
        return {"state": "deferred", "reason": "mcp_config.host_config_paths is missing or invalid", "hosts": [], "collisions": [], "host_errors": []}
    hosts: list[dict[str, Any]] = []
    collisions: list[dict[str, str]] = []
    host_errors: list[str] = []
    for path in paths:
        if not path.exists():
            if explicit_paths:
                host_errors.append(f"host MCP config not readable: {safe_path_text(path)}")
            continue
        path_error = validate_host_config_path(path)
        if path_error:
            host_errors.append(path_error)
            continue
        try:
            payload = read_json_capped(path, max_bytes=MAX_MANIFEST_FILE_BYTES, label="host MCP config")
        except (OSError, FileSizeLimitError, json.JSONDecodeError) as exc:
            host_errors.append(f"host MCP config parse failed: {safe_path_text(path)}: {type(exc).__name__}")
            continue
        if not isinstance(payload, dict):
            host_errors.append(f"host MCP config root is not object: {safe_path_text(path)}")
            continue
        host_metadata, host_collisions, metadata_errors = extract_server_metadata(path, payload)
        hosts.extend(host_metadata)
        collisions.extend(host_collisions)
        host_errors.extend(metadata_errors)
    if collisions:
        return {"state": "collision", "reason": "host MCP generated name collision", "hosts": hosts, "collisions": collisions, "host_errors": host_errors}
    if host_errors:
        return {"state": "deferred", "reason": "; ".join(host_errors[:3]), "hosts": hosts, "collisions": [], "host_errors": host_errors}
    if not hosts and not explicit_paths:
        return {"state": "deferred", "reason": "no host MCP configs found", "hosts": [], "collisions": [], "host_errors": []}
    return {"state": "clear", "reason": "host MCP metadata checked", "hosts": hosts, "collisions": [], "host_errors": []}
