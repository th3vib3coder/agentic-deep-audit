"""Minimal read-only MCP-style server for generated audit artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .audit_corpus import query_corpus
from .mcp_collision_check import GENERATED_TOOL_NAMES
from .models import ARTIFACT_PATHS


def tool_specs() -> list[dict[str, Any]]:
    return [
        {"name": "agentic_deep_audit_audit_query", "description": "Query the read-only audit corpus.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}}},
        {"name": "agentic_deep_audit_artifact_read", "description": "Read an audit-relative artifact.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
        {"name": "agentic_deep_audit_graph_neighbors", "description": "Return neighbors for a canonical graph node.", "inputSchema": {"type": "object", "properties": {"node_id": {"type": "string"}}}},
        {"name": "agentic_deep_audit_wiki_page", "description": "Read an audit wiki page by audit-relative path.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
    ]


def safe_audit_relative_path(value: str) -> bool:
    if not value or "\\" in value or ":" in value or "\x00" in value:
        return False
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        return False
    return ".." not in posix.parts and ".." not in windows.parts


def resolve_audit_artifact(audit_dir: Path, relative: str) -> Path:
    if not safe_audit_relative_path(relative):
        raise ValueError("path must be audit-relative")
    root = audit_dir.resolve()
    candidate = (root / relative).resolve()
    candidate.relative_to(root)
    if not candidate.exists() or not candidate.is_file():
        raise FileNotFoundError(relative)
    return candidate


def read_text_artifact(audit_dir: Path, relative: str, max_chars: int = 20000) -> dict[str, Any]:
    path = resolve_audit_artifact(audit_dir, relative)
    return {"path": relative, "text": path.read_text(encoding="utf-8", errors="replace")[:max_chars]}


def graph_neighbors(audit_dir: Path, node_id: str) -> dict[str, Any]:
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = json.loads(graph_path.read_text(encoding="utf-8")) if graph_path.exists() else {"nodes": [], "edges": []}
    nodes = {node.get("id"): node for node in graph.get("nodes", []) if isinstance(node, dict)}
    neighbors: list[dict[str, Any]] = []
    for edge in graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("source") == node_id and edge.get("target") in nodes:
            neighbors.append({"direction": "out", "edge": edge, "node": nodes[edge["target"]]})
        if edge.get("target") == node_id and edge.get("source") in nodes:
            neighbors.append({"direction": "in", "edge": edge, "node": nodes[edge["source"]]})
    return {"node_id": node_id, "neighbors": neighbors}


def call_tool(audit_dir: Path, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "agentic_deep_audit_audit_query":
        query = str(arguments.get("query") or "")
        limit = int(arguments.get("limit") or 10)
        return {"results": query_corpus(audit_dir, query, limit=max(1, min(limit, 50)))}
    if name == "agentic_deep_audit_artifact_read":
        return read_text_artifact(audit_dir, str(arguments.get("path") or ""))
    if name == "agentic_deep_audit_graph_neighbors":
        return graph_neighbors(audit_dir, str(arguments.get("node_id") or "repo:target"))
    if name == "agentic_deep_audit_wiki_page":
        path = str(arguments.get("path") or ARTIFACT_PATHS["WIKI_HOME"])
        if not path.startswith("wiki/"):
            raise ValueError("wiki page path must start with wiki/")
        return read_text_artifact(audit_dir, path)
    raise ValueError(f"unknown tool: {name}")


def json_rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def json_rpc_error(request_id: Any, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000, "message": message}}


def handle_request(audit_dir: Path, request: dict[str, Any]) -> dict[str, Any] | None:
    method = request.get("method")
    request_id = request.get("id")
    try:
        if method == "initialize":
            return json_rpc_result(request_id, {"serverInfo": {"name": "agentic-deep-audit", "version": "0.1.0"}, "capabilities": {"tools": {}}})
        if method == "tools/list":
            return json_rpc_result(request_id, {"tools": tool_specs()})
        if method == "tools/call":
            params = request.get("params") if isinstance(request.get("params"), dict) else {}
            payload = call_tool(audit_dir, str(params.get("name") or ""), params.get("arguments") if isinstance(params.get("arguments"), dict) else {})
            return json_rpc_result(request_id, {"content": [{"type": "text", "text": json.dumps(payload, indent=2, sort_keys=True)}]})
        if method == "notifications/initialized":
            return None
        return json_rpc_error(request_id, f"unsupported method: {method}")
    except Exception as exc:  # pragma: no cover - defensive JSON-RPC boundary
        return json_rpc_error(request_id, str(exc))


def serve_stdio(audit_dir: Path) -> int:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            response = handle_request(audit_dir, request if isinstance(request, dict) else {})
        except json.JSONDecodeError as exc:
            response = json_rpc_error(None, f"invalid JSON: {exc}")
        if response is not None:
            print(json.dumps(response, sort_keys=True), flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agentic_deep_audit.mcp_readonly_server")
    parser.add_argument("--audit-dir", required=True)
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--call-tool")
    parser.add_argument("--arguments", default="{}")
    args = parser.parse_args(argv)
    audit_dir = Path(args.audit_dir)
    if args.list_tools:
        print(json.dumps({"tools": tool_specs(), "expected_tools": GENERATED_TOOL_NAMES}, indent=2, sort_keys=True))
        return 0
    if args.call_tool:
        arguments = json.loads(args.arguments)
        payload = call_tool(audit_dir, args.call_tool, arguments if isinstance(arguments, dict) else {})
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    return serve_stdio(audit_dir)


if __name__ == "__main__":
    raise SystemExit(main())
