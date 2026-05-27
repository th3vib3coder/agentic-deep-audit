"""Validation for canonical graph, renderer and Graphify artifacts."""

from __future__ import annotations

import json
import hashlib
import re
from pathlib import Path
from typing import Any

from .audit_canonical_graph import EDGE_TYPES, NODE_TYPES, stable_slug
from .models import ARTIFACT_PATHS


EVIDENCE_RE = re.compile(r"ev-\d{6}")
DERIVED_WIKI_PAGES = {"wiki/005_graph_mermaid.md"}


def load_json(path: Path, errors: list[str]) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"invalid graph JSON artifact: {path}: {exc}")
        return {}
    if not isinstance(payload, dict):
        errors.append(f"invalid graph JSON artifact: {path}: root must be object")
        return {}
    return payload


def available_evidence(evidence_index: dict[str, Any]) -> set[str]:
    return {str(item.get("id")) for item in evidence_index.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def sha256_json(payload: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def validate_evidence_ids(location: str, value: Any, available: set[str], errors: list[str]) -> list[str]:
    if not isinstance(value, list):
        errors.append(f"{location} evidence_ids must be an array")
        return []
    evidence_ids: list[str] = []
    for item in value:
        if not isinstance(item, str) or not EVIDENCE_RE.fullmatch(item):
            errors.append(f"{location} contains invalid evidence id: {item!r}")
        elif item not in available:
            errors.append(f"{location} references unreachable evidence id: {item}")
        else:
            evidence_ids.append(item)
    return evidence_ids


def validate_node(index: int, node: Any, available: set[str], errors: list[str]) -> str | None:
    if not isinstance(node, dict):
        errors.append(f"graph node {index} must be object")
        return None
    node_id = node.get("id")
    if not isinstance(node_id, str) or not node_id:
        errors.append(f"graph node {index} missing id")
        return None
    if node.get("type") not in NODE_TYPES:
        errors.append(f"graph node {node_id} invalid type: {node.get('type')}")
    if not isinstance(node.get("label"), str) or not node["label"]:
        errors.append(f"graph node {node_id} missing label")
    validate_evidence_ids(f"graph node {node_id}", node.get("evidence_ids"), available, errors)
    return node_id


def validate_edge(index: int, edge: Any, node_ids: set[str], available: set[str], errors: list[str]) -> tuple[str, str, str] | None:
    if not isinstance(edge, dict):
        errors.append(f"graph edge {index} must be object")
        return None
    source = edge.get("source")
    target = edge.get("target")
    edge_type = edge.get("type")
    if not isinstance(source, str) or source not in node_ids:
        errors.append(f"graph edge {index} source missing from nodes: {source}")
    if not isinstance(target, str) or target not in node_ids:
        errors.append(f"graph edge {index} target missing from nodes: {target}")
    if edge_type not in EDGE_TYPES:
        errors.append(f"graph edge {index} invalid type: {edge_type}")
    for key in ["weight", "conditional", "dynamic"]:
        if key not in edge:
            errors.append(f"graph edge {index} missing {key}")
    if not isinstance(edge.get("conditional"), bool):
        errors.append(f"graph edge {index} conditional must be boolean")
    if not isinstance(edge.get("dynamic"), bool):
        errors.append(f"graph edge {index} dynamic must be boolean")
    validate_evidence_ids(f"graph edge {index}", edge.get("evidence_ids"), available, errors)
    return (str(source), str(target), str(edge_type)) if isinstance(source, str) and isinstance(target, str) and isinstance(edge_type, str) else None


def validate_derived_exports(audit_dir: Path, graph: dict[str, Any], errors: list[str]) -> None:
    nodes_payload = load_json(audit_dir / ARTIFACT_PATHS["GRAPH_NODES"], errors)
    edges_payload = load_json(audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"], errors)
    canonical_nodes = {json.dumps(node, sort_keys=True) for node in graph.get("nodes", []) if isinstance(node, dict)}
    canonical_edges = {json.dumps(edge, sort_keys=True) for edge in graph.get("edges", []) if isinstance(edge, dict)}
    derived_nodes = {json.dumps(node, sort_keys=True) for node in nodes_payload.get("nodes", []) if isinstance(node, dict)}
    derived_edges = {json.dumps(edge, sort_keys=True) for edge in edges_payload.get("edges", []) if isinstance(edge, dict)}
    if derived_nodes != canonical_nodes:
        errors.append("graph/nodes.json does not recompose canonical graph node set")
    if derived_edges != canonical_edges:
        errors.append("graph/edges.json does not recompose canonical graph edge set")


def validate_renderer_artifacts(audit_dir: Path, errors: list[str]) -> None:
    if (audit_dir / "graph" / "GRAPH_HTML_SKIPPED.md").exists():
        errors.append("GRAPH_HTML_SKIPPED.md must be emitted at audit root, not under graph/")
    html = audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]
    skipped = audit_dir / ARTIFACT_PATHS["GRAPH_HTML_SKIPPED"]
    if html.exists() and skipped.exists():
        errors.append("graph renderer emitted both graph.html and GRAPH_HTML_SKIPPED.md")
    if not html.exists() and not skipped.exists():
        errors.append("graph renderer requires graph/graph.html or root GRAPH_HTML_SKIPPED.md")
    if skipped.exists() and "Reason:" not in skipped.read_text(encoding="utf-8"):
        errors.append("GRAPH_HTML_SKIPPED.md missing Reason")


def validate_graphify_artifacts(audit_dir: Path, errors: list[str]) -> None:
    if (audit_dir / "graphify" / "GRAPHIFY_SKIPPED.md").exists():
        errors.append("GRAPHIFY_SKIPPED.md must be emitted at audit root, not under graphify/")
    skipped = audit_dir / ARTIFACT_PATHS["GRAPHIFY_SKIPPED"]
    graphify_graph = audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]
    if not skipped.exists() and not graphify_graph.exists():
        errors.append("Graphify requires root GRAPHIFY_SKIPPED.md or graphify/graph.json")
    if skipped.exists() and "Reason:" not in skipped.read_text(encoding="utf-8"):
        errors.append("GRAPHIFY_SKIPPED.md missing Reason")
    if graphify_graph.exists() and not (audit_dir / ARTIFACT_PATHS["GRAPHIFY_REPORT"]).exists():
        errors.append("graphify/GRAPH_REPORT.md required when graphify/graph.json exists")


def validate_graphify_diff(audit_dir: Path, graph: dict[str, Any], errors: list[str]) -> None:
    graphify_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]
    if not graphify_path.exists():
        return
    graphify_graph = load_json(graphify_path, errors)
    canonical_hash = sha256_json(graph)
    graphify_hash = sha256_json(graphify_graph)
    if canonical_hash == graphify_hash:
        return
    diff_path = audit_dir / ARTIFACT_PATHS["GRAPHIFY_DIFF"]
    if not diff_path.exists():
        errors.append("graphify/GRAPHIFY_DIFF.md required when Graphify graph differs from canonical graph")
        return
    text = diff_path.read_text(encoding="utf-8")
    if canonical_hash not in text or graphify_hash not in text:
        errors.append("graphify/GRAPHIFY_DIFF.md must include canonical and Graphify graph hashes")


def validate_graph_tool_status(audit_dir: Path, errors: list[str]) -> None:
    status_path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    payload = load_json(status_path, errors)
    tools = payload.get("tools") if isinstance(payload.get("tools"), list) else []
    by_name = {tool.get("tool"): tool for tool in tools if isinstance(tool, dict)}
    renderer = by_name.get("graph_html_renderer")
    graphify = by_name.get("graphify")
    if renderer is None:
        errors.append("TOOL_STATUS.json missing graph_html_renderer status")
    elif (audit_dir / ARTIFACT_PATHS["GRAPH_HTML"]).exists():
        if renderer.get("status") != "completed" or renderer.get("output_path") != ARTIFACT_PATHS["GRAPH_HTML"]:
            errors.append("graph_html_renderer status must be completed with graph/graph.html output_path")
    elif renderer.get("status") != "skipped" or not renderer.get("skipped_reason"):
        errors.append("graph_html_renderer skipped status missing skipped_reason")
    if graphify is None:
        errors.append("TOOL_STATUS.json missing graphify status")
    elif (audit_dir / ARTIFACT_PATHS["GRAPHIFY_GRAPH"]).exists():
        if graphify.get("status") != "completed" or graphify.get("output_path") != ARTIFACT_PATHS["GRAPHIFY_GRAPH"]:
            errors.append("graphify status must be completed with graphify/graph.json output_path")
    elif graphify.get("status") == "deferred" and (not graphify.get("skipped_reason") or not graphify.get("degradation_reason")):
        errors.append("graphify deferred status missing skipped/degradation reason")


def source_artifacts(graph: dict[str, Any]) -> set[str]:
    derivations = graph.get("derivations") if isinstance(graph.get("derivations"), dict) else {}
    return {str(item) for item in derivations.get("source_artifacts", []) if isinstance(item, str)}


def node_types(graph: dict[str, Any]) -> set[str]:
    return {str(node.get("type")) for node in graph.get("nodes", []) if isinstance(node, dict)}


def artifact_kinds(graph: dict[str, Any]) -> set[str]:
    return {str(node.get("artifact_kind")) for node in graph.get("nodes", []) if isinstance(node, dict) and node.get("type") == "artifact"}


def require_source_and_node(source: str, required_type: str | None, graph: dict[str, Any], sources: set[str], types: set[str], errors: list[str]) -> None:
    if source not in sources:
        errors.append(f"graph/graph.json derivations missing source artifact: {source}")
    if required_type is not None and required_type not in types:
        errors.append(f"graph/graph.json missing node type for source {source}: {required_type}")


def has_markdown_rows(path: Path) -> bool:
    if not path.exists():
        return False
    return bool(markdown_row_labels(path))


def split_markdown_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    body = stripped.strip("|")
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "|":
            cells.append("".join(current).strip(" `"))
            current = []
            continue
        current.append(char)
    cells.append("".join(current).strip(" `"))
    return cells


def markdown_row_labels(path: Path) -> list[str]:
    if not path.exists():
        return []
    labels: list[str] = []
    header_consumed = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = split_markdown_row(line)
        if not cells or all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        if not header_consumed:
            header_consumed = True
            continue
        label = cells[0].strip()
        if label and "skipped" not in line.lower():
            labels.append(label)
    return labels


def expected_graph_node_ids(audit_dir: Path, errors: list[str]) -> set[str]:
    expected: set[str] = {"repo:target"}
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"], errors) if (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).exists() else {}
    for record in file_index.get("records", []) if isinstance(file_index.get("records"), list) else []:
        if isinstance(record, dict):
            path = str(record.get("path_normalized") or record.get("path") or "")
            if path:
                expected.add(f"artifact:file:{path}")
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], errors) if (audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).exists() else {}
    for node in module_graph.get("nodes", []) if isinstance(module_graph.get("nodes"), list) else []:
        if isinstance(node, dict) and node.get("id"):
            expected.add(str(node["id"]))
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], errors) if (audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]).exists() else {}
    for symbol in symbol_index.get("symbols", []) if isinstance(symbol_index.get("symbols"), list) else []:
        if isinstance(symbol, dict) and symbol.get("symbol_id"):
            expected.add(str(symbol["symbol_id"]))
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"], errors) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {}
    for record in manifests.get("records", []) if isinstance(manifests.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        expected.add(f"artifact:manifest:{record.get('path') or 'unknown'}")
        for dependency in record.get("dependencies", []) if isinstance(record.get("dependencies"), list) else []:
            if isinstance(dependency, dict) and dependency.get("name"):
                expected.add(f"artifact:dependency:{record.get('ecosystem') or 'unknown'}:{dependency['name']}")
    for label in markdown_row_labels(audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]):
        expected.add(f"feature:{stable_slug(label)}")
    for label in markdown_row_labels(audit_dir / ARTIFACT_PATHS["PATTERNS"]):
        expected.add(f"pattern:{stable_slug(label)}")
    reuse = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], errors) if (audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]).exists() else {}
    for card in reuse.get("cards", []) if isinstance(reuse.get("cards"), list) else []:
        if isinstance(card, dict):
            identifier = str(card.get("reuse_id") or card.get("candidate_id") or card.get("name") or "")
            if identifier:
                expected.add(f"reuse:{stable_slug(identifier)}")
    for key, records_key, id_key in [("RISK_FINDINGS", "findings", "finding_id"), ("AGENTIC_SECURITY_FINDINGS", "findings", "finding_id"), ("SUSPICIOUS_BEHAVIORS", "behaviors", "behavior_id")]:
        payload = load_json(audit_dir / ARTIFACT_PATHS[key], errors) if (audit_dir / ARTIFACT_PATHS[key]).exists() else {}
        for item in payload.get(records_key, []) if isinstance(payload.get(records_key), list) else []:
            if isinstance(item, dict):
                identifier = str(item.get(id_key) or item.get("code") or "")
                if identifier:
                    expected.add(f"risk:{stable_slug(identifier)}")
    if (audit_dir / "wiki").exists():
        for path in (audit_dir / "wiki").rglob("*.md"):
            relative = path.relative_to(audit_dir).as_posix()
            if relative not in DERIVED_WIKI_PAGES:
                expected.add(f"artifact:wiki:{relative}")
    return expected


def expected_graph_edge_keys(audit_dir: Path, errors: list[str]) -> set[tuple[str, str, str]]:
    expected: set[tuple[str, str, str]] = set()
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"], errors) if (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).exists() else {}
    for record in file_index.get("records", []) if isinstance(file_index.get("records"), list) else []:
        if isinstance(record, dict):
            path = str(record.get("path_normalized") or record.get("path") or "")
            if path:
                expected.add(("repo:target", f"artifact:file:{path}", "contains"))
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], errors) if (audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).exists() else {}
    for node in module_graph.get("nodes", []) if isinstance(module_graph.get("nodes"), list) else []:
        if isinstance(node, dict) and node.get("id") and node.get("type") == "module":
            expected.add(("repo:target", str(node["id"]), "contains"))
    for edge in module_graph.get("edges", []) if isinstance(module_graph.get("edges"), list) else []:
        if isinstance(edge, dict) and edge.get("source") and edge.get("target"):
            expected.add((str(edge["source"]), str(edge["target"]), "depends_on"))
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], errors) if (audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]).exists() else {}
    for symbol in symbol_index.get("symbols", []) if isinstance(symbol_index.get("symbols"), list) else []:
        if isinstance(symbol, dict) and symbol.get("symbol_id") and symbol.get("path"):
            expected.add((f"module:{symbol['path']}", str(symbol["symbol_id"]), "contains"))
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"], errors) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {}
    for record in manifests.get("records", []) if isinstance(manifests.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        manifest_id = f"artifact:manifest:{record.get('path') or 'unknown'}"
        expected.add(("repo:target", manifest_id, "contains"))
        for dependency in record.get("dependencies", []) if isinstance(record.get("dependencies"), list) else []:
            if isinstance(dependency, dict) and dependency.get("name"):
                dep_id = f"artifact:dependency:{record.get('ecosystem') or 'unknown'}:{dependency['name']}"
                expected.add((manifest_id, dep_id, "depends_on"))
    for label in markdown_row_labels(audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]):
        expected.add(("repo:target", f"feature:{stable_slug(label)}", "implements"))
    for label in markdown_row_labels(audit_dir / ARTIFACT_PATHS["PATTERNS"]):
        expected.add(("repo:target", f"pattern:{stable_slug(label)}", "implements"))
    reuse = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], errors) if (audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]).exists() else {}
    for card in reuse.get("cards", []) if isinstance(reuse.get("cards"), list) else []:
        if isinstance(card, dict):
            identifier = str(card.get("reuse_id") or card.get("candidate_id") or card.get("name") or "")
            if identifier:
                expected.add(("repo:target", f"reuse:{stable_slug(identifier)}", "reuses"))
    for key, records_key, id_key in [("RISK_FINDINGS", "findings", "finding_id"), ("AGENTIC_SECURITY_FINDINGS", "findings", "finding_id"), ("SUSPICIOUS_BEHAVIORS", "behaviors", "behavior_id")]:
        payload = load_json(audit_dir / ARTIFACT_PATHS[key], errors) if (audit_dir / ARTIFACT_PATHS[key]).exists() else {}
        for item in payload.get(records_key, []) if isinstance(payload.get(records_key), list) else []:
            if isinstance(item, dict):
                identifier = str(item.get(id_key) or item.get("code") or "")
                if identifier:
                    expected.add((f"risk:{stable_slug(identifier)}", "repo:target", "risks"))
    if (audit_dir / "wiki").exists():
        for path in (audit_dir / "wiki").rglob("*.md"):
            relative = path.relative_to(audit_dir).as_posix()
            if relative not in DERIVED_WIKI_PAGES:
                expected.add((f"artifact:wiki:{relative}", "repo:target", "documents"))
    return expected


def validate_required_source_coverage(audit_dir: Path, graph: dict[str, Any], errors: list[str]) -> None:
    sources = source_artifacts(graph)
    types = node_types(graph)
    kinds = artifact_kinds(graph)
    if (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).exists():
        require_source_and_node(ARTIFACT_PATHS["FILE_INDEX"], "artifact", graph, sources, types, errors)
        if "file" not in kinds:
            errors.append("graph/graph.json missing file artifact nodes from FILE_INDEX.json")
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], errors) if (audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).exists() else {}
    if module_graph.get("nodes"):
        require_source_and_node(ARTIFACT_PATHS["MODULE_GRAPH"], "module", graph, sources, types, errors)
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], errors) if (audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"]).exists() else {}
    if symbol_index.get("symbols"):
        require_source_and_node(ARTIFACT_PATHS["SYMBOL_INDEX"], "symbol", graph, sources, types, errors)
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"], errors) if (audit_dir / ARTIFACT_PATHS["MANIFESTS"]).exists() else {}
    dependencies_present = any(isinstance(record, dict) and record.get("dependencies") for record in manifests.get("records", []) if isinstance(manifests.get("records"), list))
    if dependencies_present:
        require_source_and_node(ARTIFACT_PATHS["MANIFESTS"], "artifact", graph, sources, types, errors)
        if "dependency" not in kinds:
            errors.append("graph/graph.json missing dependency artifact nodes from MANIFESTS.json")
    if has_markdown_rows(audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]):
        require_source_and_node(ARTIFACT_PATHS["FEATURE_CATALOG"], "feature", graph, sources, types, errors)
    if has_markdown_rows(audit_dir / ARTIFACT_PATHS["PATTERNS"]):
        require_source_and_node(ARTIFACT_PATHS["PATTERNS"], "pattern", graph, sources, types, errors)
    reuse = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"], errors) if (audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]).exists() else {}
    if reuse.get("cards"):
        require_source_and_node(ARTIFACT_PATHS["REUSE_CARDS"], "reuse", graph, sources, types, errors)
    risk_present = False
    for key, records_key in [("RISK_FINDINGS", "findings"), ("AGENTIC_SECURITY_FINDINGS", "findings"), ("SUSPICIOUS_BEHAVIORS", "behaviors")]:
        payload = load_json(audit_dir / ARTIFACT_PATHS[key], errors) if (audit_dir / ARTIFACT_PATHS[key]).exists() else {}
        if payload.get(records_key):
            risk_present = True
            if ARTIFACT_PATHS[key] not in sources:
                errors.append(f"graph/graph.json derivations missing source artifact: {ARTIFACT_PATHS[key]}")
    if risk_present and "risk" not in types:
        errors.append("graph/graph.json missing risk nodes from risk artifacts")
    wiki_pages = [path.relative_to(audit_dir).as_posix() for path in (audit_dir / "wiki").rglob("*.md")] if (audit_dir / "wiki").exists() else []
    source_wiki = [path for path in wiki_pages if path not in DERIVED_WIKI_PAGES]
    if source_wiki:
        missing = [path for path in source_wiki if path not in sources]
        if missing:
            errors.append(f"graph/graph.json derivations missing wiki source artifacts: {', '.join(sorted(missing)[:3])}")
        if "wiki_page" not in kinds:
            errors.append("graph/graph.json missing wiki_page artifact nodes from wiki pages")
    actual_ids = {str(node.get("id")) for node in graph.get("nodes", []) if isinstance(node, dict) and node.get("id")}
    missing_ids = sorted(expected_graph_node_ids(audit_dir, errors) - actual_ids)
    if missing_ids:
        errors.append(f"graph/graph.json missing expected graph nodes: {', '.join(missing_ids[:5])}")
    actual_edges = {
        (str(edge.get("source")), str(edge.get("target")), str(edge.get("type")))
        for edge in graph.get("edges", [])
        if isinstance(edge, dict) and edge.get("source") and edge.get("target") and edge.get("type")
    }
    missing_edges = sorted(expected_graph_edge_keys(audit_dir, errors) - actual_edges)
    if missing_edges:
        preview = ", ".join(f"{source}->{target}:{edge_type}" for source, target, edge_type in missing_edges[:5])
        errors.append(f"graph/graph.json missing expected graph edges: {preview}")


def validate_canonical_graph_artifacts(audit_dir: Path, evidence_index: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    if not graph_path.exists():
        return errors
    graph = load_json(graph_path, errors)
    available = available_evidence(evidence_index)
    if graph.get("schema_version") != "1.0":
        errors.append("graph/graph.json schema_version must be 1.0")
    if not isinstance(graph.get("nodes"), list):
        errors.append("graph/graph.json requires nodes array")
        graph["nodes"] = []
    if not isinstance(graph.get("edges"), list):
        errors.append("graph/graph.json requires edges array")
        graph["edges"] = []
    node_ids = {node_id for index, node in enumerate(graph["nodes"]) if (node_id := validate_node(index, node, available, errors))}
    seen_edges: set[tuple[str, str, str]] = set()
    for index, edge in enumerate(graph["edges"]):
        key = validate_edge(index, edge, node_ids, available, errors)
        if key in seen_edges:
            errors.append(f"duplicate graph edge: {key}")
        if key is not None:
            seen_edges.add(key)
    derivations = graph.get("derivations")
    if not isinstance(derivations, dict) or not derivations.get("source_artifacts"):
        errors.append("graph/graph.json derivations.source_artifacts required")
    validate_required_source_coverage(audit_dir, graph, errors)
    validate_derived_exports(audit_dir, graph, errors)
    validate_renderer_artifacts(audit_dir, errors)
    validate_graphify_artifacts(audit_dir, errors)
    validate_graphify_diff(audit_dir, graph, errors)
    validate_graph_tool_status(audit_dir, errors)
    return errors
