"""Optional MCP config export for read-only audit artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .adapters.base import AdapterStatus, append_tool_status
from .mcp_collision_check import GENERATED_SERVER_NAME, GENERATED_TOOL_NAMES, read_host_mcp_state
from .mcp_policy import redact_value
from .models import ARTIFACT_PATHS
from .validate_corpus import validate_corpus_artifacts


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def remove_mcp_outputs(audit_dir: Path) -> None:
    for key in ["MCP_CONFIG", "MCP_DEFERRED", "MCP_COLLISION_REPORT"]:
        path = audit_dir / ARTIFACT_PATHS[key]
        if path.exists():
            path.unlink()


def append_mcp_status(audit_dir: Path, tool: str, status: str, policy: str, reason: str | None = None, output_path: str | None = None) -> None:
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool=tool,
            status=status,
            policy=policy,
            available=status == "completed",
            output_path=output_path,
            skipped_reason=reason,
            capability="mcp.export",
            availability="available" if status == "completed" else status,
            degradation_reason=reason if status == "deferred" else None,
            provenance_class="core",
        ),
    )


def corpus_is_valid(audit_dir: Path) -> tuple[bool, str | None]:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    if not evidence_index:
        return False, "EVIDENCE_INDEX.json missing; cannot validate corpus for MCP export"
    if not (audit_dir / ARTIFACT_PATHS["CORPUS_INDEX"]).exists():
        return False, "CORPUS_INDEX.json missing; MCP export requires corpus"
    errors = validate_corpus_artifacts(audit_dir, evidence_index)
    if errors:
        return False, f"corpus validation failed before MCP export: {errors[0]}"
    return True, None


def write_deferred(audit_dir: Path, reason: str) -> None:
    remove_mcp_outputs(audit_dir)
    safe_reason = str(redact_value(reason))
    path = audit_dir / ARTIFACT_PATHS["MCP_DEFERRED"]
    path.write_text(f"# MCP Deferred\n\nReason: {safe_reason}.\n", encoding="utf-8")
    append_mcp_status(audit_dir, "mcp_export", "deferred", "deferred", safe_reason, ARTIFACT_PATHS["MCP_DEFERRED"])


def write_collision_report(audit_dir: Path, state: dict[str, Any]) -> None:
    remove_mcp_outputs(audit_dir)
    safe_reason = str(redact_value(str(state.get("reason") or "")))
    lines = ["# MCP Collision Report", "", f"Reason: {safe_reason}.", "", "## Collisions", ""]
    for collision in state.get("collisions", []):
        host_path = str(redact_value(str(collision.get("host_path") or "")))
        lines.append(f"- server `{collision.get('server_name')}` exposes conflicting tool `{collision.get('tool_name')}` from `{host_path}`.")
    lines.extend(["", "## Host Metadata Read", ""])
    for host in state.get("hosts", []):
        host_path = str(redact_value(str(host.get("host_path") or "")))
        lines.append(f"- path: `{host_path}`")
        lines.append(f"  server: `{host.get('server_name')}`")
        lines.append(f"  tools: {', '.join(f'`{name}`' for name in host.get('tool_names', [])) or '`<none>`'}")
        lines.append(f"  resources: {', '.join(f'`{name}`' for name in host.get('resource_names', [])) or '`<none>`'}")
        lines.append(f"  prompts: {', '.join(f'`{name}`' for name in host.get('prompt_names', [])) or '`<none>`'}")
        lines.append(f"  command_args: omitted; count={host.get('arg_count', 0)}")
    lines.extend(["", "Recommendation: rename the conflicting host MCP tool before enabling this generated config.", ""])
    path = audit_dir / ARTIFACT_PATHS["MCP_COLLISION_REPORT"]
    path.write_text("\n".join(lines), encoding="utf-8")
    append_mcp_status(audit_dir, "mcp_export", "blocked", "blocked", str(state.get("reason")), ARTIFACT_PATHS["MCP_COLLISION_REPORT"])


def generated_mcp_config() -> dict[str, Any]:
    tools = [{"name": name, "read_only": True} for name in GENERATED_TOOL_NAMES]
    return {
        "mcpServers": {
            GENERATED_SERVER_NAME: {
                "command": "python",
                "args": ["-m", "agentic_deep_audit.mcp_readonly_server", "--audit-dir", "${AGENTIC_DEEP_AUDIT_AUDIT_DIR}"],
                "env": {"AGENTIC_DEEP_AUDIT_AUDIT_DIR": "${AGENTIC_DEEP_AUDIT_AUDIT_DIR}"},
                "read_only": True,
                "tools": tools,
                "resources": [
                    {"name": "agentic_deep_audit_corpus", "path": ARTIFACT_PATHS["CORPUS_INDEX"], "read_only": True},
                    {"name": "agentic_deep_audit_graph", "path": ARTIFACT_PATHS["GRAPH"], "read_only": True},
                    {"name": "agentic_deep_audit_wiki_home", "path": ARTIFACT_PATHS["WIKI_HOME"], "read_only": True},
                ],
            }
        }
    }


def write_mcp_config(audit_dir: Path) -> None:
    remove_mcp_outputs(audit_dir)
    write_json(audit_dir / ARTIFACT_PATHS["MCP_CONFIG"], generated_mcp_config())
    append_mcp_status(audit_dir, "mcp_export", "completed", "allowed", output_path=ARTIFACT_PATHS["MCP_CONFIG"])


def run_mcp_export(run_config: dict[str, Any], audit_dir: Path) -> None:
    ok, reason = corpus_is_valid(audit_dir)
    if not ok:
        write_deferred(audit_dir, reason or "corpus unavailable")
        return
    state = read_host_mcp_state(run_config)
    if state["state"] == "unknown":
        append_mcp_status(audit_dir, "mcp_collision_check", "deferred", "host_mcp_read_exception", str(state["reason"]))
        write_deferred(audit_dir, str(state["reason"]))
        return
    if state["state"] == "collision":
        append_mcp_status(audit_dir, "mcp_collision_check", "blocked", "host_mcp_read_exception", str(state["reason"]))
        write_collision_report(audit_dir, state)
        return
    append_mcp_status(audit_dir, "mcp_collision_check", "completed", "host_mcp_read_exception")
    write_mcp_config(audit_dir)
