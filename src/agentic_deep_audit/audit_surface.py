"""Public API, CLI, MCP and configuration surface extraction."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS
from .sanitize import sanitize_markdown


SURFACE_STATUS = {"observed", "heuristic", "skipped"}
MARKDOWN_EXTENSIONS = {".md", ".markdown", ".rst", ".txt", ".adoc"}
MCP_NAMES = {".mcp.json", "mcp.json", "mcp-config.json"}
MCP_PATH_SUFFIXES = {".cursor/mcp.json", ".vscode/mcp.json", ".claude/mcp.json"}
CONFIG_NAMES = {
    ".env",
    ".env.example",
    ".env.sample",
    "audit.config.yaml",
    "audit.config.yml",
    "audit.config.json",
    "pyproject.toml",
    "package.json",
    "cargo.toml",
    "go.mod",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
}
ENV_PATTERNS = [
    re.compile(r"os\.environ(?:\.get)?\(\s*['\"]([A-Z_][A-Z0-9_]*)['\"]"),
    re.compile(r"process\.env\.([A-Z_][A-Z0-9_]*)"),
    re.compile(r"process\.env\[['\"]([A-Z_][A-Z0-9_]*)['\"]\]"),
    re.compile(r"ENV\[['\"]([A-Z_][A-Z0-9_]*)['\"]\]"),
    re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}"),
    re.compile(r"(?m)^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*="),
]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_by_path(audit_dir: Path) -> dict[str, list[str]]:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    result: dict[str, list[str]] = {}
    for item in evidence_index.get("evidence", []):
        if isinstance(item, dict) and item.get("path") and item.get("id"):
            result.setdefault(str(item["path"]), []).append(str(item["id"]))
    return result


def repo_path_from(audit_dir: Path, run_config: dict[str, Any]) -> Path:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    return Path(str((file_index.get("repo") or {}).get("path") or (run_config.get("repo") or {}).get("path") or ".")).resolve()


def sanitizer_decision(repo_path: Path, relative_path: str, evidence_ids: list[str]) -> str:
    suffix = Path(relative_path).suffix.lower()
    if suffix not in MARKDOWN_EXTENSIONS:
        return "not_markdown"
    try:
        text = (repo_path / relative_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "skipped"
    return sanitize_markdown(relative_path, text, evidence_id=evidence_ids[0] if evidence_ids else None).decision


def surface_record(
    prefix: str,
    index: int,
    kind: str,
    source_path: str,
    evidence_ids: list[str],
    repo_path: Path,
    status: str = "observed",
    confidence: str = "medium",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "surface_id": f"{prefix}-{index:06d}",
        "kind": kind,
        "source_path": source_path,
        "status": status,
        "confidence": confidence,
        "evidence_ids": sorted(set(evidence_ids)),
        "sanitizer_decision": sanitizer_decision(repo_path, source_path, evidence_ids),
        **extra,
    }


def read_text(repo_path: Path, relative_path: str) -> str:
    return (repo_path / relative_path).read_text(encoding="utf-8", errors="replace")


def route_records(records: list[dict[str, Any]], evidence_lookup: dict[str, list[str]], repo_path: Path) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for file_record in records:
        path = str(file_record.get("path_normalized") or file_record.get("path") or "")
        if not path or bool(file_record.get("binary")):
            continue
        suffix = Path(path).suffix.lower()
        if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".graphql", ".gql", ".proto"}:
            continue
        text = read_text(repo_path, path)
        evidence_ids = evidence_lookup.get(path, [])
        for method, route_path, framework in extract_rest_routes(text, suffix):
            routes.append(
                surface_record(
                    "api",
                    len(routes) + 1,
                    "rest_route",
                    path,
                    evidence_ids,
                    repo_path,
                    confidence="high",
                    method=method,
                    path=route_path,
                    framework=framework,
                )
            )
        for name, framework in extract_schema_routes(text, suffix):
            routes.append(
                surface_record(
                    "api",
                    len(routes) + 1,
                    framework,
                    path,
                    evidence_ids,
                    repo_path,
                    status="heuristic",
                    confidence="medium",
                    method=None,
                    path=name,
                    framework=framework,
                )
            )
    return routes


def extract_rest_routes(text: str, suffix: str) -> list[tuple[str, str, str]]:
    routes: list[tuple[str, str, str]] = []
    if suffix == ".py":
        for match in re.finditer(r"@(?:app|router|api)\.(get|post|put|patch|delete|websocket)\(\s*['\"]([^'\"]+)['\"]", text):
            method = "WEBSOCKET" if match.group(1) == "websocket" else match.group(1).upper()
            routes.append((method, match.group(2), "fastapi_or_flask_decorator"))
        for match in re.finditer(r"@(?:app|blueprint)\.route\(\s*['\"]([^'\"]+)['\"](?:,\s*methods\s*=\s*\[([^\]]+)\])?", text):
            methods = re.findall(r"['\"]([A-Z]+)['\"]", match.group(2) or "") or ["GET"]
            routes.extend((method, match.group(1), "flask_route") for method in methods)
    if suffix in {".js", ".jsx", ".ts", ".tsx"}:
        for match in re.finditer(r"\b(?:app|router|fastify)\.(get|post|put|patch|delete|ws)\(\s*['\"]([^'\"]+)['\"]", text):
            method = "WEBSOCKET" if match.group(1) == "ws" else match.group(1).upper()
            routes.append((method, match.group(2), "js_router"))
        if re.search(r"\bnew\s+(?:WebSocket\.Server|WebSocketServer|ws\.Server)\b", text):
            routes.append(("WEBSOCKET", "<websocket-server>", "websocket"))
    return routes


def extract_schema_routes(text: str, suffix: str) -> list[tuple[str, str]]:
    routes: list[tuple[str, str]] = []
    if suffix in {".graphql", ".gql"} or re.search(r"\btype\s+Query\b|\bschema\s*{", text):
        routes.append(("graphql://schema", "graphql"))
    if suffix == ".proto":
        for match in re.finditer(r"\bservice\s+([A-Za-z_]\w*)", text):
            routes.append((f"grpc://{match.group(1)}", "grpc"))
    return routes


def cli_records(audit_dir: Path, repo_path: Path, evidence_lookup: dict[str, list[str]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    manifests_path = audit_dir / ARTIFACT_PATHS["MANIFESTS"]
    if manifests_path.exists():
        manifests = load_json(manifests_path)
        for manifest in manifests.get("records", []):
            if not isinstance(manifest, dict):
                continue
            source_path = str(manifest.get("path") or "")
            for command in manifest.get("scripts") or []:
                records.append(
                    surface_record(
                        "cli",
                        len(records) + 1,
                        "manifest_script",
                        source_path,
                        list(manifest.get("evidence_ids") or []),
                        repo_path,
                        status="observed",
                        confidence="high",
                        command=command.get("command"),
                        category=command.get("category"),
                        executable=False,
                        observed_not_executed=True,
                        policy_rule=command.get("policy_rule"),
                    )
                )
    records.extend(package_bin_records(repo_path, evidence_lookup, len(records)))
    records.extend(cargo_bin_records(repo_path, evidence_lookup, len(records)))
    records.extend(go_command_records(repo_path, evidence_lookup, len(records)))
    records.extend(python_entrypoint_records(audit_dir, repo_path, len(records)))
    return records


def package_bin_records(repo_path: Path, evidence_lookup: dict[str, list[str]], offset: int) -> list[dict[str, Any]]:
    path = repo_path / "package.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    bins = payload.get("bin")
    items = bins.items() if isinstance(bins, dict) else ([(payload.get("name") or "node-bin", bins)] if isinstance(bins, str) else [])
    records: list[dict[str, Any]] = []
    for name, target in items:
        records.append(surface_record("cli", offset + len(records) + 1, "node_bin", "package.json", evidence_lookup.get("package.json", []), repo_path, status="observed", confidence="high", name=str(name), entrypoint=str(target), executable=False, observed_not_executed=True))
    return records


def cargo_bin_records(repo_path: Path, evidence_lookup: dict[str, list[str]], offset: int) -> list[dict[str, Any]]:
    path = repo_path / "Cargo.toml"
    if not path.exists():
        return []
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return []
    records: list[dict[str, Any]] = []
    for item in payload.get("bin") or []:
        if isinstance(item, dict) and item.get("name"):
            records.append(surface_record("cli", offset + len(records) + 1, "cargo_bin", "Cargo.toml", evidence_lookup.get("Cargo.toml", []), repo_path, status="observed", confidence="high", name=str(item["name"]), entrypoint=str(item.get("path") or ""), executable=False, observed_not_executed=True))
    return records


def go_command_records(repo_path: Path, evidence_lookup: dict[str, list[str]], offset: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted((repo_path / "cmd").glob("*/main.go")) if (repo_path / "cmd").exists() else []:
        relative = path.relative_to(repo_path).as_posix()
        records.append(surface_record("cli", offset + len(records) + 1, "go_command", relative, evidence_lookup.get(relative, []), repo_path, status="heuristic", confidence="medium", name=path.parent.name, entrypoint=relative, executable=False, observed_not_executed=True))
    return records


def python_entrypoint_records(audit_dir: Path, repo_path: Path, offset: int) -> list[dict[str, Any]]:
    symbol_path = audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]
    if not symbol_path.exists():
        return []
    symbols = load_json(symbol_path).get("symbols", [])
    records: list[dict[str, Any]] = []
    for symbol in symbols:
        if isinstance(symbol, dict) and symbol.get("kind") == "entrypoint":
            source_path = str(symbol.get("path") or "")
            records.append(surface_record("cli", offset + len(records) + 1, "python_main_guard", source_path, list(symbol.get("evidence_ids") or []), repo_path, status="heuristic", confidence="medium", name="__main__", entrypoint=source_path, executable=False, observed_not_executed=True))
    return records


def mcp_records(records: list[dict[str, Any]], evidence_lookup: dict[str, list[str]], repo_path: Path) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    for file_record in records:
        path = str(file_record.get("path_normalized") or file_record.get("path") or "")
        lowered = path.lower()
        if Path(lowered).name not in MCP_NAMES and lowered not in MCP_PATH_SUFFIXES:
            continue
        server_names: list[str] = []
        try:
            payload = json.loads(read_text(repo_path, path))
            servers = payload.get("mcpServers") if isinstance(payload.get("mcpServers"), dict) else payload.get("servers")
            if isinstance(servers, dict):
                server_names = sorted(str(name) for name in servers)
        except json.JSONDecodeError:
            server_names = []
        surfaces.append(
            surface_record(
                "mcp",
                len(surfaces) + 1,
                "target_mcp_config",
                path,
                evidence_lookup.get(path, []),
                repo_path,
                status="observed",
                confidence="high",
                server_names=server_names,
                host_imported=False,
                audit_only=True,
            )
        )
    return surfaces


def config_records(records: list[dict[str, Any]], evidence_lookup: dict[str, list[str]], repo_path: Path) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    for file_record in records:
        path = str(file_record.get("path_normalized") or file_record.get("path") or "")
        if not path or bool(file_record.get("binary")):
            continue
        lowered_name = Path(path).name.lower()
        suffix = Path(path).suffix.lower()
        evidence_ids = evidence_lookup.get(path, [])
        if lowered_name in CONFIG_NAMES or file_record.get("kind") == "config":
            surfaces.append(surface_record("config", len(surfaces) + 1, "config_file", path, evidence_ids, repo_path, status="observed", confidence="high", name=Path(path).name))
        try:
            text = read_text(repo_path, path)
        except OSError:
            continue
        for env_name in sorted(set(extract_env_var_names(text))):
            surfaces.append(surface_record("config", len(surfaces) + 1, "env_var", path, evidence_ids, repo_path, status="observed" if suffix not in MARKDOWN_EXTENSIONS else "heuristic", confidence="high" if suffix not in MARKDOWN_EXTENSIONS else "medium", name=env_name, value_read=False))
    return surfaces


def extract_env_var_names(text: str) -> list[str]:
    names: list[str] = []
    for pattern in ENV_PATTERNS:
        names.extend(match.group(1) for match in pattern.finditer(text))
    return names


def surface_payload(run_config: dict[str, Any], audit_dir: Path, records: list[dict[str, Any]], source_artifacts: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "run_id": run_config.get("run_id"),
        "repo": run_config.get("repo") or {},
        "source_artifacts": source_artifacts,
        "records": records,
        "skipped": False,
        "skip_reason": None,
        "coverage": {"record_count": len(records), "status_values": sorted(SURFACE_STATUS)},
    }


def run_surface(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    records = [record for record in file_index.get("records", []) if isinstance(record, dict)]
    repo_path = repo_path_from(audit_dir, run_config)
    evidence_lookup = evidence_by_path(audit_dir)
    api = route_records(records, evidence_lookup, repo_path)
    cli = cli_records(audit_dir, repo_path, evidence_lookup)
    mcp = mcp_records(records, evidence_lookup, repo_path)
    config = config_records(records, evidence_lookup, repo_path)
    common_sources = [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["EVIDENCE_INDEX"]]
    write_json(audit_dir / ARTIFACT_PATHS["API_SURFACE"], surface_payload(run_config, audit_dir, api, common_sources))
    write_json(audit_dir / ARTIFACT_PATHS["CLI_SURFACE"], surface_payload(run_config, audit_dir, cli, [*common_sources, ARTIFACT_PATHS["MANIFESTS"], ARTIFACT_PATHS["SYMBOL_INDEX"]]))
    write_json(audit_dir / ARTIFACT_PATHS["MCP_SURFACE"], surface_payload(run_config, audit_dir, mcp, common_sources))
    write_json(audit_dir / ARTIFACT_PATHS["CONFIG_SURFACE"], surface_payload(run_config, audit_dir, config, common_sources))
