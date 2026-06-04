"""Canonical graph export derived from audit artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .artifact_io import write_json_artifact
from .audit_graph_renderers import write_graph_renderer_outputs, write_graphify_outputs
from .limits import FileSizeLimitError, MAX_ARTIFACT_FILE_BYTES, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS
from .wiki_frontmatter import frontmatter_evidence_ids


NODE_TYPES = {"repo", "module", "symbol", "feature", "pattern", "risk", "reuse", "artifact"}
EDGE_TYPES = {"contains", "depends_on", "implements", "documents", "evidences", "risks", "reuses"}
EVIDENCE_RE = re.compile(r"ev-\d{6,}")

# B08: the single canonical root node id, referenced from every layer. A constant prevents
# the literal drifting and documents the (current) single-repo assumption in one place.
REPO_NODE_ID = "repo:target"


class CanonicalGraphError(ValueError):
    """Raised when a node/edge is constructed with a type outside the closed contract."""


def normalize_graph_path(value: Any) -> str:
    # B09: canonical node ids must use POSIX separators so a Windows-produced symbol path
    # (src\foo.py) still resolves to its module node (module:src/foo.py) instead of dangling.
    return str(value).replace("\\", "/")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = read_json_capped(path, max_bytes=MAX_ARTIFACT_FILE_BYTES, label="canonical graph input")
    except (OSError, FileSizeLimitError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_artifact(path, payload)


def stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-").lower()
    return slug or "unnamed"


def evidence_from_text(text: str) -> list[str]:
    return sorted(set(EVIDENCE_RE.findall(text)))


def wiki_frontmatter_evidence_ids(text: str) -> list[str]:
    # Thin delegate to the shared single-source-of-truth helper (was a byte-duplicate of
    # audit_corpus.trusted_wiki_evidence_ids; swarm-flagged drift risk — now both forward to one impl).
    return frontmatter_evidence_ids(text)


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


def evidence_by_path(evidence_index: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in evidence_index.get("evidence", []):
        if isinstance(item, dict) and item.get("path") and item.get("id"):
            result.setdefault(str(item["path"]), []).append(str(item["id"]))
    return {key: sorted(set(values)) for key, values in result.items()}


def add_node(nodes: dict[str, dict[str, Any]], node_id: str, node_type: str, label: str, evidence_ids: list[str] | None = None, **extra: Any) -> None:
    if node_type not in NODE_TYPES:
        # B06: silently relabelling an unknown node type to "artifact" hid contract drift and
        # passed schema validation on laundered data. Fail loud so the caller is fixed.
        raise CanonicalGraphError(f"unknown canonical node type: {node_type!r}")
    existing = nodes.get(node_id)
    if existing is None:
        nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "evidence_ids": sorted(set(evidence_ids or [])),
            **{key: value for key, value in extra.items() if value is not None},
        }
        return
    existing["evidence_ids"] = sorted(set(existing.get("evidence_ids", [])) | set(evidence_ids or []))


def add_edge(
    edges: dict[tuple[str, str, str], dict[str, Any]],
    source: str,
    target: str,
    edge_type: str,
    evidence_ids: list[str] | None = None,
    weight: float = 1.0,
    conditional: bool = False,
    dynamic: bool = False,
) -> None:
    if edge_type not in EDGE_TYPES:
        # B06: silently relabelling an unknown edge type to "documents" hid contract drift.
        raise CanonicalGraphError(f"unknown canonical edge type: {edge_type!r}")
    key = (source, target, edge_type)
    existing = edges.get(key)
    if existing is None:
        edges[key] = {
            "source": source,
            "target": target,
            "type": edge_type,
            "weight": weight,
            "conditional": conditional,
            "dynamic": dynamic,
            "evidence_ids": sorted(set(evidence_ids or [])),
        }
        return
    # B03 canonical mirror: duplicate source/target/type edges from distinct sites must preserve
    # total signal instead of keeping whichever import site happened to arrive first.
    existing["weight"] = float(existing.get("weight") or 0.0) + float(weight)
    existing["conditional"] = bool(existing.get("conditional")) or bool(conditional)
    existing["dynamic"] = bool(existing.get("dynamic")) or bool(dynamic)
    existing["evidence_ids"] = sorted(set(existing.get("evidence_ids", [])) | set(evidence_ids or []))


def artifact_node_id(path: str) -> str:
    return f"artifact:{path}"


def add_file_nodes(audit_dir: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], source_artifacts: set[str]) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    evidence_lookup = evidence_by_path(load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]))
    if not file_index:
        return
    source_artifacts.add(ARTIFACT_PATHS["FILE_INDEX"])
    for record in file_index.get("records", []) if isinstance(file_index.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        path = str(record.get("path_normalized") or record.get("path") or "")
        if not path:
            continue
        node_id = artifact_node_id(f"file:{path}")
        evidence_ids = evidence_lookup.get(path, [])
        add_node(nodes, node_id, "artifact", path, evidence_ids, artifact_kind="file", path=path)
        add_edge(edges, REPO_NODE_ID, node_id, "contains", evidence_ids)


def add_module_and_symbol_nodes(
    nodes: dict[str, dict[str, Any]],
    edges: dict[tuple[str, str, str], dict[str, Any]],
    module_graph: dict[str, Any],
    symbol_index: dict[str, Any],
    source_artifacts: set[str],
) -> None:
    source_artifacts.update({ARTIFACT_PATHS["MODULE_GRAPH"], ARTIFACT_PATHS["SYMBOL_INDEX"]})
    for node in module_graph.get("nodes", []) if isinstance(module_graph.get("nodes"), list) else []:
        if not isinstance(node, dict) or not node.get("id"):
            continue
        node_id = str(node["id"])
        evidence_ids = [str(item) for item in node.get("evidence_ids", []) if isinstance(item, str)]
        source_type = str(node.get("type") or "")
        if source_type == "module":
            add_node(nodes, node_id, "module", str(node.get("path") or node_id), evidence_ids, path=node.get("path"))
            add_edge(edges, REPO_NODE_ID, node_id, "contains", evidence_ids)
        else:
            add_node(nodes, node_id, "artifact", str(node.get("path") or node_id), evidence_ids, artifact_kind=source_type or "dependency")
    for symbol in symbol_index.get("symbols", []) if isinstance(symbol_index.get("symbols"), list) else []:
        if not isinstance(symbol, dict) or not symbol.get("symbol_id"):
            continue
        node_id = str(symbol["symbol_id"])
        evidence_ids = [str(item) for item in symbol.get("evidence_ids", []) if isinstance(item, str)]
        add_node(nodes, node_id, "symbol", str(symbol.get("name") or node_id), evidence_ids, path=symbol.get("path"), kind=symbol.get("kind"))
        if symbol.get("path"):
            add_edge(edges, f"module:{normalize_graph_path(symbol['path'])}", node_id, "contains", evidence_ids)
    pre_edge_node_ids = set(nodes)
    for edge in module_graph.get("edges", []) if isinstance(module_graph.get("edges"), list) else []:
        if not isinstance(edge, dict) or not edge.get("source") or not edge.get("target"):
            continue
        target = str(edge["target"])
        edge_evidence = [str(item) for item in edge.get("evidence_ids", []) if isinstance(item, str)]
        # FIX-GRAPHVAL (2026-06-03; minor hardening 2026-06-04): a module-graph edge target that never became
        # a node -- notably package:<dynamic> (resolve_import_target returns it for unresolvable/relative
        # imports) -- was DROPPED by build_canonical_graph's endpoint filter (dropped_edge_count>0 +
        # missing-expected-edge; hermes-agent). Materialise an artifact node for such SYNTHETIC targets so the
        # edge is preserved. Test `pre_edge_node_ids` (frozen BEFORE this loop), not the live `nodes`, so
        # MULTIPLE edges to the same synthetic target UNION their evidence (add_node merges) while real
        # module/symbol/package nodes are never re-touched. artifact_kind mirrors the resolved-package
        # convention (a `package:` target -> "package", else "dependency").
        if target not in pre_edge_node_ids:
            add_node(nodes, target, "artifact", target, edge_evidence,
                     artifact_kind="package" if target.startswith("package:") else "dependency")
        add_edge(
            edges,
            str(edge["source"]),
            target,
            "depends_on",
            edge_evidence,
            weight=float(edge.get("weight") or 1.0),
            conditional=bool(edge.get("conditional")),
            dynamic=bool(edge.get("dynamic")),
        )


def add_manifest_dependency_nodes(audit_dir: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], source_artifacts: set[str]) -> None:
    manifests = load_json(audit_dir / ARTIFACT_PATHS["MANIFESTS"])
    if not manifests:
        return
    source_artifacts.add(ARTIFACT_PATHS["MANIFESTS"])
    for record in manifests.get("records", []) if isinstance(manifests.get("records"), list) else []:
        if not isinstance(record, dict):
            continue
        evidence_ids = [str(item) for item in record.get("evidence_ids", []) if isinstance(item, str)]
        manifest_id = artifact_node_id(f"manifest:{record.get('path') or 'unknown'}")
        add_node(nodes, manifest_id, "artifact", str(record.get("path") or "manifest"), evidence_ids, artifact_kind="manifest")
        add_edge(edges, REPO_NODE_ID, manifest_id, "contains", evidence_ids)
        for dependency in record.get("dependencies", []) if isinstance(record.get("dependencies"), list) else []:
            if not isinstance(dependency, dict) or not dependency.get("name"):
                continue
            dep_id = artifact_node_id(f"dependency:{record.get('ecosystem') or 'unknown'}:{dependency['name']}")
            add_node(nodes, dep_id, "artifact", str(dependency["name"]), evidence_ids, artifact_kind="dependency", scope=dependency.get("scope"))
            add_edge(edges, manifest_id, dep_id, "depends_on", evidence_ids)


def markdown_table_rows(path: Path) -> list[tuple[str, list[str]]]:
    if not path.exists():
        return []
    rows: list[tuple[str, list[str]]] = []
    header_consumed = False
    try:
        text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="canonical graph markdown")
    except (OSError, FileSizeLimitError):
        return []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = split_markdown_row(line)
        if not cells or all(re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        if not header_consumed:
            header_consumed = True
            continue
        label = cells[0].strip() if cells else ""
        if label:
            rows.append((label, evidence_from_text(line)))
    return rows


def available_evidence_ids(audit_dir: Path) -> set[str]:
    index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("id")) for item in index.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def add_markdown_concept_nodes(
    audit_dir: Path,
    nodes: dict[str, dict[str, Any]],
    edges: dict[tuple[str, str, str], dict[str, Any]],
    source_artifacts: set[str],
) -> None:
    available = available_evidence_ids(audit_dir)
    for key, node_type, edge_type in [("FEATURE_CATALOG", "feature", "implements"), ("PATTERNS", "pattern", "implements")]:
        artifact = ARTIFACT_PATHS[key]
        path = audit_dir / artifact
        if not path.exists():
            continue
        source_artifacts.add(artifact)
        for label, evidence_ids in markdown_table_rows(path):
            # FIX-GRAPHVAL (2026-06-03, swarm follow-up): filter the row's regex-harvested ids against the
            # REAL evidence index (mirroring the wiki generator's `if match in available` guard). A blanket
            # ev-\d{6,} harvest over the whole row also matches a coincidental substring in a PATH/label cell
            # (e.g. `src/dev-123456/x.py` -> phantom `ev-123456`) that the cell sanitizer does not escape when
            # there is no word boundary -- a phantom reference that would block REPORT.md. Same bug class as
            # the wiki-slug phantom (Fix B). Empty available (no index / unit test) keeps all (fail-safe).
            clean_evidence = [eid for eid in evidence_ids if not available or eid in available]
            node_id = f"{node_type}:{stable_slug(label)}"
            add_node(nodes, node_id, node_type, label, clean_evidence, source_artifact=artifact)
            add_edge(edges, REPO_NODE_ID, node_id, edge_type, clean_evidence)


def add_risk_nodes(audit_dir: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], source_artifacts: set[str]) -> None:
    for key, records_key, id_key in [("RISK_FINDINGS", "findings", "finding_id"), ("AGENTIC_SECURITY_FINDINGS", "findings", "finding_id"), ("SUSPICIOUS_BEHAVIORS", "behaviors", "behavior_id")]:
        artifact = ARTIFACT_PATHS[key]
        payload = load_json(audit_dir / artifact)
        if not payload:
            continue
        source_artifacts.add(artifact)
        for item in payload.get(records_key, []) if isinstance(payload.get(records_key), list) else []:
            if not isinstance(item, dict):
                continue
            identifier = str(item.get(id_key) or item.get("code") or f"{key.lower()}-{len(nodes)}")
            evidence_ids = [str(value) for value in item.get("evidence_ids", []) if isinstance(value, str)]
            node_id = f"risk:{stable_slug(identifier)}"
            add_node(nodes, node_id, "risk", identifier, evidence_ids, severity=item.get("severity"), source_artifact=artifact)
            add_edge(edges, node_id, REPO_NODE_ID, "risks", evidence_ids)


def add_reuse_nodes(audit_dir: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], source_artifacts: set[str]) -> None:
    artifact = ARTIFACT_PATHS["REUSE_CARDS"]
    payload = load_json(audit_dir / artifact)
    if not payload:
        return
    source_artifacts.add(artifact)
    for card in payload.get("cards", []) if isinstance(payload.get("cards"), list) else []:
        if not isinstance(card, dict):
            continue
        identifier = str(card.get("reuse_id") or card.get("candidate_id") or card.get("name") or f"reuse-{len(nodes)}")
        evidence_ids = [str(value) for value in card.get("evidence_ids", []) if isinstance(value, str)]
        node_id = f"reuse:{stable_slug(identifier)}"
        add_node(nodes, node_id, "reuse", str(card.get("name") or identifier), evidence_ids, decision=card.get("decision"), source_artifact=artifact)
        add_edge(edges, REPO_NODE_ID, node_id, "reuses", evidence_ids)


def add_wiki_nodes(audit_dir: Path, nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], source_artifacts: set[str]) -> None:
    wiki_root = audit_dir / "wiki"
    if not wiki_root.exists():
        return
    for path in sorted(wiki_root.rglob("*.md")):
        relative = path.relative_to(audit_dir).as_posix()
        source_artifacts.add(relative)
        try:
            text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="canonical graph wiki")
        except (OSError, FileSizeLimitError):
            continue
        evidence_ids = wiki_frontmatter_evidence_ids(text)
        node_id = artifact_node_id(f"wiki:{relative}")
        add_node(nodes, node_id, "artifact", relative, evidence_ids, artifact_kind="wiki_page", path=relative)
        add_edge(edges, node_id, REPO_NODE_ID, "documents", evidence_ids)


def build_canonical_graph(audit_dir: Path, run_config: dict[str, Any], module_graph: dict[str, Any], symbol_index: dict[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    source_artifacts: set[str] = set()
    add_node(nodes, REPO_NODE_ID, "repo", "target", [])
    add_file_nodes(audit_dir, nodes, edges, source_artifacts)
    add_manifest_dependency_nodes(audit_dir, nodes, edges, source_artifacts)
    add_module_and_symbol_nodes(nodes, edges, module_graph, symbol_index, source_artifacts)
    add_markdown_concept_nodes(audit_dir, nodes, edges, source_artifacts)
    add_risk_nodes(audit_dir, nodes, edges, source_artifacts)
    add_reuse_nodes(audit_dir, nodes, edges, source_artifacts)
    add_wiki_nodes(audit_dir, nodes, edges, source_artifacts)
    graph_nodes = sorted(nodes.values(), key=lambda item: item["id"])
    node_ids = {node["id"] for node in graph_nodes}
    graph_edges = sorted((edge for edge in edges.values() if edge["source"] in node_ids and edge["target"] in node_ids), key=lambda item: (item["source"], item["target"], item["type"]))
    # B15: an edge whose endpoint never became a node (e.g. a symbol path that did not match any
    # module node) was silently discarded. Record how many were dropped so the validator and
    # downstream consumers can tell "no orphan edges" from "orphans hidden".
    dropped_edges = sum(1 for edge in edges.values() if edge["source"] not in node_ids or edge["target"] not in node_ids)
    return {
        "schema_version": "1.0",
        "repo": run_config.get("repo") or {},
        "nodes": graph_nodes,
        "edges": graph_edges,
        "derivations": {
            "source_artifacts": sorted(source_artifacts),
            "derived_exports": [ARTIFACT_PATHS["GRAPH_NODES"], ARTIFACT_PATHS["GRAPH_EDGES"]],
            "node_count": len(graph_nodes),
            "edge_count": len(graph_edges),
            "dropped_edge_count": dropped_edges,
        },
    }


def write_derived_exports(audit_dir: Path, graph: dict[str, Any]) -> None:
    write_json(audit_dir / ARTIFACT_PATHS["GRAPH"], graph)
    write_json(audit_dir / ARTIFACT_PATHS["GRAPH_NODES"], {"schema_version": "1.0", "nodes": graph["nodes"]})
    write_json(audit_dir / ARTIFACT_PATHS["GRAPH_EDGES"], {"schema_version": "1.0", "edges": graph["edges"]})


def run_canonical_graph_outputs(run_config: dict[str, Any], audit_dir: Path, module_graph: dict[str, Any] | None = None, symbol_index: dict[str, Any] | None = None) -> None:
    module_graph = module_graph if module_graph is not None else load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    symbol_index = symbol_index if symbol_index is not None else load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"])
    graph = build_canonical_graph(audit_dir, run_config, module_graph, symbol_index)
    write_derived_exports(audit_dir, graph)
    write_graph_renderer_outputs(audit_dir, run_config, graph)
    write_graphify_outputs(audit_dir, graph, run_config)
