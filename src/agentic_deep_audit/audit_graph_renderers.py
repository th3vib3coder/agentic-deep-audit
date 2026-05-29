"""Renderer and Graphify outputs derived from the canonical graph."""

from __future__ import annotations

import hashlib
import html
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .adapters.base import AdapterStatus, adapter_subprocess_env, append_tool_status
from .adapters.loader import AdapterBlockedPrePromotion, validate_adapter_promotion
from .limits import FileSizeLimitError, read_json_capped
from .models import ARTIFACT_PATHS, PLUGIN_ROOT
from .policy import append_blocked_attempt, decide_command


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
INVISIBLE_CHARS = "\u00ad\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\ufeff"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = read_json_capped(path, label="graph renderer input")
    except (OSError, FileSizeLimitError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def sha256_json(payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def html_text(value: Any) -> str:
    return html.escape(str(value), quote=True)


def mermaid_label(value: Any, max_length: int = 160) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("```", "` ` `")
    text = "".join(char for char in text if char not in INVISIBLE_CHARS)
    text = html.escape(text, quote=True)
    text = text.replace("[", "&#91;").replace("]", "&#93;")
    text = text[:max_length]
    return json.dumps(text)


def mermaid_lines(graph: dict[str, Any]) -> list[str]:
    node_ids = {str(node["id"]): f"n{index}" for index, node in enumerate(graph.get("nodes", [])[:50], start=1) if isinstance(node, dict)}
    labels = {str(node.get("id")): str(node.get("label") or node.get("id")) for node in graph.get("nodes", []) if isinstance(node, dict)}
    lines = ["```mermaid", "graph TD"]
    for node_id, mermaid_id in node_ids.items():
        label = mermaid_label(labels.get(node_id, node_id))
        lines.append(f"  {mermaid_id}[{label}]")
    for edge in graph.get("edges", [])[:80]:
        if not isinstance(edge, dict):
            continue
        source = node_ids.get(str(edge.get("source")))
        target = node_ids.get(str(edge.get("target")))
        if source and target:
            lines.append(f"  {source} --> {target}")
    lines.append("```")
    return lines


def write_mermaid_fallback(audit_dir: Path, graph: dict[str, Any]) -> None:
    wiki_root = audit_dir / "wiki"
    if not wiki_root.exists():
        return
    path = wiki_root / "005_graph_mermaid.md"
    body = [
        "---",
        'title: "Canonical Graph Mermaid"',
        'type: "graph"',
        'repo: "target"',
        'commit: "unknown"',
        'slug: "005_graph_mermaid"',
        'tags: ["agentic-deep-audit", "graph"]',
        f'source_artifacts: {json.dumps([ARTIFACT_PATHS["GRAPH"]])}',
        "evidence_ids: []",
        'status: "skipped"',
        "---",
        "",
        "# Canonical Graph Mermaid",
        "",
        "## Purpose",
        "",
        "Render a compact Mermaid fallback from the canonical graph when HTML rendering is unavailable.",
        "",
        "## Key Evidence",
        "",
        "- skipped: graph rendering is derived from `graph/graph.json`.",
        "",
        "## Open Questions",
        "",
        "- Promote a local HTML renderer before relying on rich graph navigation.",
        "",
        *mermaid_lines(graph),
        "",
    ]
    path.write_text("\n".join(body), encoding="utf-8")


def write_builtin_html(audit_dir: Path, graph: dict[str, Any]) -> Path:
    path = audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]
    path.parent.mkdir(parents=True, exist_ok=True)
    nodes = graph.get("nodes", []) if isinstance(graph.get("nodes"), list) else []
    edges = graph.get("edges", []) if isinstance(graph.get("edges"), list) else []
    rows = "\n".join(
        f"<li><code>{html_text(node.get('id'))}</code> ({html_text(node.get('type'))}): {html_text(node.get('label'))}</li>"
        for node in nodes[:200]
        if isinstance(node, dict)
    )
    edge_rows = "\n".join(
        f"<li><code>{html_text(edge.get('source'))}</code> -&gt; <code>{html_text(edge.get('target'))}</code> ({html_text(edge.get('type'))})</li>"
        for edge in edges[:300]
        if isinstance(edge, dict)
    )
    html = f"""<!doctype html>
<html lang=\"en\">
<head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Agentic Deep Audit Graph</title></head>
<body>
<h1>Canonical Graph</h1>
<p>Derived from <code>graph/graph.json</code>. Nodes: {len(nodes)}. Edges: {len(edges)}.</p>
<h2>Nodes</h2>
<ul>{rows}</ul>
<h2>Edges</h2>
<ul>{edge_rows}</ul>
</body>
</html>
"""
    path.write_text(html, encoding="utf-8")
    return path


def write_graph_renderer_outputs(audit_dir: Path, run_config: dict[str, Any], graph: dict[str, Any]) -> None:
    renderer = str(((run_config.get("graph") or {}).get("html_renderer") or "pyvis")).lower()
    html_path = audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]
    skip_path = audit_dir / ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"]
    if renderer in {"builtin", "internal", "html"}:
        output = write_builtin_html(audit_dir, graph)
        if skip_path.exists():
            skip_path.unlink()
        append_tool_status(
            audit_dir,
            AdapterStatus(
                tool="graph_html_renderer",
                status="completed",
                policy="allowed",
                available=True,
                version="builtin",
                output_path=output.relative_to(audit_dir).as_posix(),
                capability="graph.render",
                availability="available",
                provenance_class="core",
                notes=["renderer=builtin"],
            ),
        )
        return
    if renderer in {"none", "json"}:
        reason = f"renderer {renderer} requested JSON-only output"
    elif renderer == "pyvis" and shutil.which("pyvis") is None:
        reason = "pyvis renderer not promoted/installed; Mermaid wiki fallback emitted when wiki exists"
    elif renderer == "mermaid":
        reason = "Mermaid fallback emitted in wiki; standalone HTML renderer skipped"
    else:
        reason = f"renderer {renderer} not available under adapter promotion gate"
    write_mermaid_fallback(audit_dir, graph)
    if html_path.exists():
        html_path.unlink()
    skip_path.write_text(f"# Graph HTML Skipped\n\nReason: {reason}.\n", encoding="utf-8")
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool="graph_html_renderer",
            status="skipped",
            policy="skipped",
            available=False,
            skipped_reason=reason,
            capability="graph.render",
            availability="missing",
            provenance_class="industry-known",
        ),
    )


def graph_hashes(canonical: dict[str, Any], graphify_graph: dict[str, Any]) -> tuple[str, str]:
    return sha256_json(canonical), sha256_json(graphify_graph)


def markdown_fence_text(value: str) -> str:
    """Render tool output inside a Markdown fence without allowing fence breakout."""

    cleaned = ANSI_ESCAPE_RE.sub("", value)
    cleaned = "".join(char for char in cleaned if ord(char) >= 32 or char in {"\n", "\t"})
    cleaned = "".join(char for char in cleaned if char not in INVISIBLE_CHARS)
    return cleaned.replace("```", "`\u200b``").strip()


def markdown_inline_text(value: str) -> str:
    """Render a one-line Markdown field derived from tool output."""

    return markdown_fence_text(value).replace("\r", " ").replace("\n", " ")


def write_graphify_report(audit_dir: Path, status: str, command: list[str], stdout: str, stderr: str, canonical_hash: str, graphify_hash: str | None) -> None:
    report = audit_dir / ARTIFACT_PATHS["GRAPHIFY_REPORT"]
    report.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Graphify Report",
        "",
        f"- Status: `{status}`",
        f"- Command: `{' '.join(command)}`",
        f"- Canonical graph hash: `{canonical_hash}`",
    ]
    if graphify_hash is not None:
        lines.append(f"- Graphify graph hash: `{graphify_hash}`")
    if stdout.strip():
        lines.extend(["", "## Stdout", "", "```text", markdown_fence_text(stdout), "```"])
    if stderr.strip():
        lines.extend(["", "## Stderr", "", "```text", markdown_fence_text(stderr), "```"])
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_graphify_diff(audit_dir: Path, canonical_hash: str, graphify_hash: str) -> None:
    path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_DIFF"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Graphify Diff",
                "",
                "Graphify output differs from the canonical graph. Canonical graph remains authoritative.",
                "",
                f"- canonical_sha256: `{canonical_hash}`",
                f"- graphify_sha256: `{graphify_hash}`",
                "",
            ]
        ),
        encoding="utf-8",
    )


def record_graphify_skip(audit_dir: Path, graph: dict[str, Any], reason: str, status: str, availability: str, command: list[str] | None = None, duration_ms: int | None = None, exit_code: int | None = None) -> None:
    skip_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]
    safe_reason = markdown_inline_text(reason)
    skip_path.write_text(f"# Graphify Skipped\n\nReason: {safe_reason}.\nCanonical graph hash: `{sha256_json(graph)}`.\n", encoding="utf-8")
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool="graphify",
            status=status,
            policy="blocked" if status == "blocked" else "skipped" if status in {"skipped", "deferred"} else "allowed",
            available=status in {"completed", "failed"},
            command=command,
            duration_ms=duration_ms,
            exit_code=exit_code,
            skipped_reason=reason,
            capability="graph.external_renderer",
            availability=availability,
            provenance_class="industry-known",
            degradation_reason=reason if status == "deferred" else None,
        ),
    )


def write_graphify_outputs(audit_dir: Path, graph: dict[str, Any], run_config: dict[str, Any] | None = None) -> None:
    canonical_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graphify_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]
    graphify_mode = str((((run_config or {}).get("graph") or {}).get("graphify") or "auto")).lower()
    if graphify_mode in {"disabled", "disable", "off", "false", "never"}:
        if graphify_path.exists():
            graphify_path.unlink()
        record_graphify_skip(audit_dir, graph, "Graphify disabled by run configuration", "skipped", "disabled")
        return
    try:
        validate_adapter_promotion(PLUGIN_ROOT, "graphify", "industry-known")
    except AdapterBlockedPrePromotion as exc:
        reason = str(exc)
        skip_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]
        skip_path.write_text(f"# Graphify Skipped\n\nReason: {reason}.\nCanonical graph remains `graph/graph.json`.\n", encoding="utf-8")
        append_tool_status(
            audit_dir,
            AdapterStatus(
                tool="graphify",
                status="deferred",
                policy="skipped",
                available=False,
                skipped_reason=reason,
                capability="graph.external_renderer",
                availability="deferred",
                provenance_class="industry-known",
                degradation_reason=reason,
            ),
        )
        return
    if shutil.which("graphify") is None:
        record_graphify_skip(
            audit_dir,
            graph,
            "Graphify promotion exists but graphify executable is not installed",
            "skipped",
            "missing",
        )
        return
    command = ["graphify", "--input", canonical_path.as_posix(), "--output", graphify_path.as_posix()]
    decision = decide_command(command, origin="plugin_allowlist")
    if not decision.allowed:
        append_blocked_attempt(audit_dir, decision)
        record_graphify_skip(audit_dir, graph, decision.reason, "blocked", "blocked", command=command)
        return
    graphify_path.parent.mkdir(parents=True, exist_ok=True)
    canonical_before = canonical_path.read_bytes()
    started = time.monotonic()
    completed = subprocess.run(command, cwd=audit_dir, env=adapter_subprocess_env(), text=True, encoding="utf-8", errors="replace", capture_output=True, check=False, timeout=30)
    duration_ms = int((time.monotonic() - started) * 1000)
    try:
        canonical_after = canonical_path.read_bytes()
    except OSError:
        canonical_after = None
    if canonical_after != canonical_before:
        canonical_path.write_bytes(canonical_before)
        if graphify_path.exists():
            graphify_path.unlink()
        diff_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_DIFF"]
        if diff_path.exists():
            diff_path.unlink()
        reason = "Graphify attempted to mutate canonical graph; restored graph/graph.json and skipped adapter output"
        record_graphify_skip(audit_dir, graph, reason, "failed", "failed", command, duration_ms, completed.returncode)
        return
    if completed.returncode != 0 or not graphify_path.exists():
        reason = completed.stderr.strip()[:200] or "Graphify did not produce graphify/graph.json"
        record_graphify_skip(audit_dir, graph, reason, "failed", "failed", command, duration_ms, completed.returncode)
        return
    graphify_graph = load_json(graphify_path)
    canonical_hash, graphify_hash = graph_hashes(graph, graphify_graph)
    write_graphify_report(audit_dir, "completed", command, completed.stdout, completed.stderr, canonical_hash, graphify_hash)
    if canonical_hash != graphify_hash:
        write_graphify_diff(audit_dir, canonical_hash, graphify_hash)
    skip_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]
    if skip_path.exists():
        skip_path.unlink()
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool="graphify",
            status="completed",
            policy="allowed",
            available=True,
            command=command,
            duration_ms=duration_ms,
            exit_code=completed.returncode,
            output_path=ARTIFACT_PATHS["GRAPHIFY_GRAPH"],
            capability="graph.external_renderer",
            availability="available",
            provenance_class="industry-known",
        ),
    )
