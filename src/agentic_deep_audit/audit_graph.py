"""Static module, symbol and call graph extraction."""

from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters.base import AdapterStatus, append_tool_status
from .artifact_io import write_json_artifact
from .audit_canonical_graph import run_canonical_graph_outputs
from .limits import FileSizeLimitError, read_bytes_capped, read_json_capped, read_text_auto_capped
from .models import ARTIFACT_PATHS


PY_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
GO_EXTENSIONS = {".go"}
RUST_EXTENSIONS = {".rs"}
JAVA_KOTLIN_EXTENSIONS = {".java", ".kt", ".kts"}
GENERIC_EXTENSIONS = {".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".rb", ".php"}
GRAPH_EXTENSIONS = PY_EXTENSIONS | JS_EXTENSIONS | GO_EXTENSIONS | RUST_EXTENSIONS | JAVA_KOTLIN_EXTENSIONS | GENERIC_EXTENSIONS
DEFAULT_CENTRALITY = "weighted_in_degree"
ALLOWED_CENTRALITY = {DEFAULT_CENTRALITY, "degree_total", "pagerank_if_available"}


@dataclass
class GraphState:
    repo_path: Path
    records: list[dict[str, Any]]
    evidence_by_path: dict[str, list[str]]
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[tuple[str, str, str, bool, bool], dict[str, Any]] = field(default_factory=dict)
    symbols: dict[str, dict[str, Any]] = field(default_factory=dict)
    call_nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    call_edges: dict[tuple[str, str, bool, bool], dict[str, Any]] = field(default_factory=dict)
    coverage_notes: list[str] = field(default_factory=list)
    language_counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def local_code_paths(self) -> set[str]:
        return {
            str(record["path_normalized"])
            for record in self.records
            if str(record.get("extension") or "").lower() in GRAPH_EXTENSIONS and not record.get("binary")
        }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json_artifact(path, payload)


def load_json(path: Path) -> dict[str, Any]:
    return read_json_capped(path, label="graph input")


def evidence_map(evidence_index: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for item in evidence_index.get("evidence", []):
        if isinstance(item, dict) and item.get("path") and item.get("id"):
            result[str(item["path"])].append(str(item["id"]))
    return dict(result)


def node_id(path: str) -> str:
    return f"module:{path}"


def package_id(name: str) -> str:
    return f"package:{name}"


def symbol_id(path: str, name: str, kind: str, line: int) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "anonymous"
    return f"symbol:{path}:{kind}:{safe_name}:{line}"


def line_span(data: bytes, start_line: int, end_line: int) -> dict[str, int]:
    starts = [0]
    for index, byte in enumerate(data):
        if byte == 10:
            starts.append(index + 1)
    start_index = max(0, min(start_line - 1, len(starts) - 1))
    if end_line < len(starts):
        end_byte = starts[end_line]
    else:
        end_byte = len(data)
    return {
        "start_line": start_line,
        "end_line": max(start_line, end_line),
        "start_byte": starts[start_index],
        "end_byte": max(starts[start_index], end_byte),
    }


def read_source_bytes(state: GraphState, path: str) -> bytes | None:
    try:
        return read_bytes_capped(state.repo_path / path, label="graph source")
    except FileSizeLimitError as exc:
        state.coverage_notes.append(f"{path}: graph parse skipped: {exc}")
        return None


def add_module_node(state: GraphState, path: str) -> None:
    state.nodes.setdefault(
        node_id(path),
        {"id": node_id(path), "type": "module", "path": path, "evidence_ids": state.evidence_by_path.get(path, [])},
    )


def add_package_node(state: GraphState, name: str) -> None:
    state.nodes.setdefault(package_id(name), {"id": package_id(name), "type": "package", "path": name, "evidence_ids": []})


def add_edge(state: GraphState, source: str, target: str, edge_type: str, weight: float, conditional: bool, dynamic: bool, evidence_ids: list[str]) -> None:
    if source == target:
        # B04: a node referencing itself corrupts weighted-in-degree and gives PageRank
        # perpetual positive feedback. Record the occurrence but do not create an edge.
        state.coverage_notes.append(f"{source}: self-referential {edge_type} edge skipped")
        return
    key = (source, target, edge_type, conditional, dynamic)
    existing = state.edges.get(key)
    if existing is None:
        state.edges[key] = {
            "source": source,
            "target": target,
            "type": edge_type,
            "weight": weight,
            "conditional": conditional,
            "dynamic": dynamic,
            "evidence_ids": sorted(set(evidence_ids)),
        }
        return
    # B03: distinct import sites that share (source, target, type, conditional, dynamic) must
    # sum their weights so centrality reflects import frequency instead of a single deduped edge.
    existing["weight"] = float(existing.get("weight") or 0.0) + float(weight)
    existing["evidence_ids"] = sorted(set(existing.get("evidence_ids", [])) | set(evidence_ids))


def add_symbol(state: GraphState, path: str, name: str, kind: str, span: dict[str, int], public: bool, evidence_ids: list[str], exported: bool | None = None) -> str:
    sid = symbol_id(path, name, kind, span["start_line"])
    state.symbols.setdefault(
        sid,
        {
            "symbol_id": sid,
            "name": name,
            "kind": kind,
            "path": path,
            "span": span,
            "public": public,
            "exported": public if exported is None else exported,
            "evidence_ids": sorted(set(evidence_ids)),
        },
    )
    return sid


def add_call(state: GraphState, caller: str, callee: str, path: str, conditional: bool, dynamic: bool, evidence_ids: list[str]) -> None:
    state.call_nodes.setdefault(caller, {"id": caller, "kind": "symbol", "label": caller.split(":")[-2], "path": path, "evidence_ids": evidence_ids})
    callee_id = f"external:{callee}" if not callee.startswith("symbol:") else callee
    state.call_nodes.setdefault(callee_id, {"id": callee_id, "kind": "external" if callee_id.startswith("external:") else "symbol", "label": callee, "path": None, "evidence_ids": []})
    key = (caller, callee_id, conditional, dynamic)
    state.call_edges.setdefault(
        key,
        {"caller": caller, "callee": callee_id, "type": "calls", "conditional": conditional, "dynamic": dynamic, "evidence_ids": sorted(set(evidence_ids))},
    )


def resolve_import_target(state: GraphState, current_path: str, module: str | None, level: int = 0) -> str:
    if not module:
        return package_id("<dynamic>")
    candidates: list[str] = []
    if level > 0:
        base = Path(current_path).parent
        for _ in range(max(0, level - 1)):
            base = base.parent
        candidates.append((base / (module.replace(".", "/") + ".py")).as_posix())
        candidates.append((base / module.replace(".", "/") / "__init__.py").as_posix())
    else:
        candidates.append(module.replace(".", "/") + ".py")
        candidates.append(module.replace(".", "/") + "/__init__.py")
    for candidate in candidates:
        if candidate in state.local_code_paths:
            add_module_node(state, candidate)
            return node_id(candidate)
    top = module.split(".", 1)[0]
    add_package_node(state, top)
    return package_id(top)


def resolve_js_target(state: GraphState, current_path: str, specifier: str) -> str:
    if specifier.startswith("."):
        base = Path(current_path).parent / specifier
        candidates = [base.with_suffix(ext).as_posix() for ext in [".ts", ".tsx", ".js", ".jsx"]]
        candidates.extend((base / f"index{ext}").as_posix() for ext in [".ts", ".tsx", ".js", ".jsx"])
        for candidate in candidates:
            normalized = str(Path(candidate).as_posix()).replace("\\", "/")
            if normalized in state.local_code_paths:
                add_module_node(state, normalized)
                return node_id(normalized)
    top = specifier.split("/", 1)[0]
    add_package_node(state, top)
    return package_id(top)


class PythonExtractor(ast.NodeVisitor):
    def __init__(self, state: GraphState, path: str, data: bytes) -> None:
        self.state = state
        self.path = path
        self.data = data
        self.evidence_ids = state.evidence_by_path.get(path, [])
        self.current_symbol: str | None = None
        self.class_stack: list[str] = []
        self.conditional_depth = 0

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            target = resolve_import_target(self.state, self.path, alias.name, 0)
            add_edge(self.state, node_id(self.path), target, "imports", 0.5 if self.conditional_depth else 1.0, bool(self.conditional_depth), False, self.evidence_ids)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target = resolve_import_target(self.state, self.path, node.module, node.level)
        add_edge(self.state, node_id(self.path), target, "imports", 0.5 if self.conditional_depth else 1.0, bool(self.conditional_depth), False, self.evidence_ids)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        sid = add_symbol(self.state, self.path, node.name, "class", line_span(self.data, node.lineno, getattr(node, "end_lineno", node.lineno)), not node.name.startswith("_"), self.evidence_ids)
        previous = self.current_symbol
        self.current_symbol = sid
        self.class_stack.append(node.name)
        self._decorators(node)
        self.generic_visit(node)
        self.class_stack.pop()
        self.current_symbol = previous

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function(node)

    def visit_If(self, node: ast.If) -> None:
        if is_main_guard(node.test):
            add_symbol(self.state, self.path, "__main__", "entrypoint", line_span(self.data, node.lineno, node.lineno), True, self.evidence_ids, True)
        self.visit(node.test)
        self.conditional_depth += 1
        for child in node.body + node.orelse:
            self.visit(child)
        self.conditional_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if self.current_symbol is not None:
            name, dynamic = call_name(node.func)
            add_call(self.state, self.current_symbol, name, self.path, bool(self.conditional_depth), dynamic, self.evidence_ids)
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        name = f"{self.class_stack[-1]}.{node.name}" if self.class_stack else node.name
        kind = "method" if self.class_stack else "function"
        sid = add_symbol(self.state, self.path, name, kind, line_span(self.data, node.lineno, getattr(node, "end_lineno", node.lineno)), not node.name.startswith("_"), self.evidence_ids)
        previous = self.current_symbol
        self.current_symbol = sid
        self._decorators(node)
        self.generic_visit(node)
        self.current_symbol = previous

    def _decorators(self, node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            name, _ = call_name(decorator)
            add_symbol(self.state, self.path, name, "decorator", line_span(self.data, decorator.lineno, decorator.lineno), True, self.evidence_ids, True)


def is_main_guard(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "__name__"
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == "__main__"
    )


def call_name(node: ast.AST) -> tuple[str, bool]:
    if isinstance(node, ast.Name):
        return node.id, False
    if isinstance(node, ast.Attribute):
        base, dynamic = call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr, dynamic
    return "<dynamic_call>", True


def parse_python(state: GraphState, path: str) -> None:
    data = read_source_bytes(state, path)
    if data is None:
        return
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path)
    except (SyntaxError, UnicodeDecodeError) as exc:
        state.coverage_notes.append(f"{path}: python parse skipped: {exc}")
        return
    PythonExtractor(state, path, data).visit(tree)


def parse_js_ts(state: GraphState, path: str) -> None:
    data = read_source_bytes(state, path)
    if data is None:
        return
    text = data.decode("utf-8", errors="replace")
    evidence_ids = state.evidence_by_path.get(path, [])
    # B05: line-based conditional tracking is heuristic. We recognize the common conditional
    # openers (if / else if / while / for) instead of only `if (`, and we never let the depth
    # go negative when closing braces outnumber tracked openers (function bodies also use `{}`).
    # When a file contains conditional imports we flag the heuristic so downstream consumers do
    # not treat the conditional/non-conditional split as exact.
    conditional_depth = 0
    conditional_import_seen = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        leading_closers = len(re.match(r"^}*", stripped).group(0))
        if leading_closers and conditional_depth:
            conditional_depth = max(0, conditional_depth - leading_closers)
        remainder = stripped[leading_closers:].lstrip()
        if re.match(r"(?:else\s+)?if\s*\(", remainder) or re.match(r"else\s*\{", remainder) or re.match(r"(?:while|for)\s*\(", remainder):
            conditional_depth += 1
        for pattern in [r"\bimport(?:[^'\"]*\bfrom\s*)?['\"]([^'\"]+)['\"]", r"\bexport\s+.*\bfrom\s+['\"]([^'\"]+)['\"]", r"\brequire\(\s*['\"]([^'\"]+)['\"]\s*\)"]:
            for match in re.finditer(pattern, line):
                target = resolve_js_target(state, path, match.group(1))
                conditional = bool(conditional_depth)
                conditional_import_seen = conditional_import_seen or conditional
                add_edge(state, node_id(path), target, "imports", 0.5 if conditional else 1.0, conditional, False, evidence_ids)
        if "require(" in line and not re.search(r"require\(\s*['\"]", line):
            state.coverage_notes.append(f"{path}:{line_number}: dynamic require skipped")
        for pattern in [r"\bexport\s+function\s+([A-Za-z_$][\w$]*)", r"\bexport\s+(?:const|let|var|class)\s+([A-Za-z_$][\w$]*)", r"module\.exports"]:
            match = re.search(pattern, line)
            if match:
                name = match.group(1) if match.groups() else "module.exports"
                add_symbol(state, path, name, "export", line_span(data, line_number, line_number), True, evidence_ids, True)
        trailing_closers = remainder.count("}")
        if trailing_closers and conditional_depth:
            conditional_depth = max(0, conditional_depth - trailing_closers)
    if conditional_import_seen:
        state.coverage_notes.append(f"{path}: javascript conditional-import detection is heuristic")


def parse_go(state: GraphState, path: str) -> None:
    data = read_source_bytes(state, path)
    if data is None:
        return
    text = data.decode("utf-8", errors="replace")
    evidence_ids = state.evidence_by_path.get(path, [])
    for line_number, line in enumerate(text.splitlines(), start=1):
        import_match = re.search(r'"([^"]+)"', line) if "import" in line or line.strip().startswith('"') else None
        if import_match:
            add_package_node(state, import_match.group(1))
            add_edge(state, node_id(path), package_id(import_match.group(1)), "imports", 1.0, False, False, evidence_ids)
        func_match = re.search(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)", line)
        if func_match:
            add_symbol(state, path, func_match.group(1), "function", line_span(data, line_number, line_number), True, evidence_ids)
    state.coverage_notes.append(f"{path}: go parser minimal")


def parse_rust(state: GraphState, path: str) -> None:
    data = read_source_bytes(state, path)
    if data is None:
        return
    text = data.decode("utf-8", errors="replace")
    evidence_ids = state.evidence_by_path.get(path, [])
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"\b(?:use|mod)\s+([A-Za-z_][\w:]*)", line)
        if match:
            name = match.group(1).replace("::", "/")
            add_package_node(state, name)
            add_edge(state, node_id(path), package_id(name), "imports", 1.0, False, False, evidence_ids)
        func_match = re.search(r"\bfn\s+([A-Za-z_]\w*)", line)
        if func_match:
            add_symbol(state, path, func_match.group(1), "function", line_span(data, line_number, line_number), not func_match.group(1).startswith("_"), evidence_ids)
    state.coverage_notes.append(f"{path}: rust parser minimal")


def parse_java_kotlin(state: GraphState, path: str) -> None:
    data = read_source_bytes(state, path)
    if data is None:
        return
    text = data.decode("utf-8", errors="replace")
    evidence_ids = state.evidence_by_path.get(path, [])
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = re.search(r"\bimport\s+([A-Za-z_][\w.]*)(?:\.\*)?;", line)
        if match:
            add_package_node(state, match.group(1))
            add_edge(state, node_id(path), package_id(match.group(1)), "imports", 1.0, False, False, evidence_ids)
        class_match = re.search(r"\b(?:class|interface|object)\s+([A-Za-z_]\w*)", line)
        if class_match:
            add_symbol(state, path, class_match.group(1), "class", line_span(data, line_number, line_number), True, evidence_ids)
    state.coverage_notes.append(f"{path}: java/kotlin parser minimal")


def parse_generic(state: GraphState, path: str) -> None:
    state.coverage_notes.append(f"{path}: no language parser available; module node only")


def extract_graph(state: GraphState) -> None:
    for record in sorted(state.records, key=lambda item: str(item.get("path_normalized"))):
        path = str(record.get("path_normalized") or record.get("path"))
        suffix = str(record.get("extension") or Path(path).suffix).lower()
        if record.get("binary") or suffix not in GRAPH_EXTENSIONS:
            continue
        add_module_node(state, path)
        if suffix in PY_EXTENSIONS:
            state.language_counts["python"] += 1
            parse_python(state, path)
        elif suffix in JS_EXTENSIONS:
            state.language_counts["js_ts"] += 1
            parse_js_ts(state, path)
        elif suffix in GO_EXTENSIONS:
            state.language_counts["go"] += 1
            parse_go(state, path)
        elif suffix in RUST_EXTENSIONS:
            state.language_counts["rust"] += 1
            parse_rust(state, path)
        elif suffix in JAVA_KOTLIN_EXTENSIONS:
            state.language_counts["java_kotlin"] += 1
            parse_java_kotlin(state, path)
        else:
            state.language_counts["generic"] += 1
            parse_generic(state, path)


def record_sizes(records: list[dict[str, Any]]) -> dict[str, int]:
    return {node_id(str(record.get("path_normalized") or record.get("path"))): int(record.get("size_bytes") or 0) for record in records}


def compute_centrality(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], algorithm: str = DEFAULT_CENTRALITY, sizes: dict[str, int] | None = None) -> dict[str, dict[str, float | int | str]]:
    if algorithm not in ALLOWED_CENTRALITY:
        raise ValueError(f"unsupported centrality algorithm: {algorithm}")
    ids = [node["id"] for node in nodes if node.get("type") == "module"]
    scores = {identifier: 0.0 for identifier in ids}
    if algorithm == "weighted_in_degree":
        for edge in edges:
            if edge["source"] == edge["target"]:  # B04 defense-in-depth
                continue
            if edge["target"] in scores:
                scores[edge["target"]] += float(edge.get("weight") or 0.0)
    elif algorithm == "degree_total":
        for edge in edges:
            if edge["source"] == edge["target"]:  # B04 defense-in-depth
                continue
            if edge["target"] in scores:
                scores[edge["target"]] += float(edge.get("weight") or 0.0)
            if edge["source"] in scores:
                scores[edge["source"]] += float(edge.get("weight") or 0.0)
    else:
        scores = pagerank(ids, edges)
    sizes = sizes or {}
    ordered = sorted(scores, key=lambda item: (-scores[item], -sizes.get(item, 0), item))
    return {identifier: {"algorithm": algorithm, "score": scores[identifier], "rank": index + 1} for index, identifier in enumerate(ordered)}


def pagerank(ids: list[str], edges: list[dict[str, Any]]) -> dict[str, float]:
    if not ids:
        return {}
    # B10: membership tests use a set (O(1)) instead of scanning the id list (O(V)); dangling
    # mass is redistributed once per iteration instead of per-source (was O(D*V) -> O(V)).
    ids_set = set(ids)
    count = len(ids)
    outgoing: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        if source == target:  # B04: self-loops give PageRank perpetual positive feedback
            continue
        if source in ids_set and target in ids_set:
            outgoing[source].append((target, float(edge.get("weight") or 1.0)))
    scores = {identifier: 1.0 / count for identifier in ids}
    damping = 0.85
    base = (1.0 - damping) / count
    for _ in range(20):
        next_scores = {identifier: base for identifier in ids}
        dangling_mass = 0.0
        for source in ids:
            out = outgoing.get(source)
            total = sum(weight for _, weight in out) if out else 0.0
            if total == 0.0:
                dangling_mass += scores[source]
                continue
            for target, weight in out:
                next_scores[target] += damping * scores[source] * (weight / total)
        if dangling_mass:
            share = damping * dangling_mass / count
            for identifier in ids:
                next_scores[identifier] += share
        scores = next_scores
    return scores


def graph_coverage(state: GraphState) -> dict[str, Any]:
    return {
        "languages": dict(sorted(state.language_counts.items())),
        "partial": bool(state.coverage_notes),
        "notes": sorted(set(state.coverage_notes)),
    }


def architecture_baseline(module_graph: dict[str, Any], symbol_index: dict[str, Any]) -> str:
    module_count = len(module_graph.get("nodes", []))
    edge_count = len(module_graph.get("edges", []))
    symbol_count = len(symbol_index.get("symbols", []))
    top_modules = sorted(
        ((node_id_, info["score"]) for node_id_, info in module_graph.get("centrality", {}).items()),
        key=lambda item: (-float(item[1]), item[0]),
    )[:5]
    lines = [
        "## Baseline",
        "",
        f"- Module nodes: {module_count}",
        f"- Module edges: {edge_count}",
        f"- Symbols indexed: {symbol_count}",
        "",
        "### Top Modules By Centrality",
        "",
    ]
    if top_modules:
        lines.extend(f"- `{module}`: {score:.3f}" for module, score in top_modules)
    else:
        lines.append("- No module centrality available.")
    lines.append("")
    return "\n".join(lines)


def write_architecture(path: Path, baseline: str) -> None:
    if not path.exists():
        path.write_text("# Architecture\n\n" + baseline, encoding="utf-8")
        return
    text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="architecture").replace("\r\n", "\n").replace("\r", "\n")
    if "## Baseline" not in text:
        path.write_text(text.rstrip() + "\n\n" + baseline, encoding="utf-8")
        return
    start = text.index("## Baseline")
    next_match = re.search(r"\n## (?!Baseline\b)", text[start + len("## Baseline") :])
    if next_match is None:
        preserved = text[:start].rstrip()
        path.write_text((preserved + "\n\n" if preserved else "") + baseline, encoding="utf-8")
        return
    end = start + len("## Baseline") + next_match.start()
    path.write_text(text[:start].rstrip() + "\n\n" + baseline + text[end:], encoding="utf-8")


def append_centrality_status(audit_dir: Path, algorithm: str) -> None:
    note = f"algorithm={algorithm}"
    if algorithm != DEFAULT_CENTRALITY:
        note = f"override algorithm={algorithm}; default={DEFAULT_CENTRALITY}"
    append_tool_status(
        audit_dir,
        AdapterStatus(
            tool="centrality_scorer",
            status="detected",
            policy="allowed",
            available=True,
            version="internal",
            capability="graph.centrality",
            availability="available",
            provenance_class="core",
            notes=[note],
        ),
    )


def run_graph(run_config: dict[str, Any], audit_dir: Path) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or (run_config.get("repo") or {}).get("path") or ".")).resolve()
    records = [record for record in file_index.get("records", []) if isinstance(record, dict)]
    state = GraphState(repo_path=repo_path, records=records, evidence_by_path=evidence_map(evidence_index))
    extract_graph(state)

    nodes = sorted(state.nodes.values(), key=lambda item: item["id"])
    edges = sorted(state.edges.values(), key=lambda item: (item["source"], item["target"], item["type"]))
    graph_config = run_config.get("graph") if isinstance(run_config.get("graph"), dict) else {}
    centrality_config = graph_config.get("centrality") if isinstance(graph_config.get("centrality"), dict) else {}
    algorithm = str(centrality_config.get("algorithm") or DEFAULT_CENTRALITY)
    centrality = compute_centrality(nodes, edges, algorithm, record_sizes(records))
    coverage = graph_coverage(state)
    module_graph = {
        "schema_version": "1.0",
        "nodes": nodes,
        "edges": edges,
        "coverage": coverage,
        "partial_reason": "; ".join(coverage["notes"]) if coverage["notes"] else None,
        "centrality": centrality,
    }
    symbol_index = {"schema_version": "1.0", "symbols": sorted(state.symbols.values(), key=lambda item: item["symbol_id"]), "coverage": coverage}
    write_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], module_graph)
    write_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], symbol_index)
    run_canonical_graph_outputs(run_config, audit_dir, module_graph, symbol_index)
    if state.call_edges:
        write_json(
            audit_dir / ARTIFACT_PATHS["CALL_GRAPH"],
            {
                "schema_version": "1.0",
                "nodes": sorted(state.call_nodes.values(), key=lambda item: item["id"]),
                "edges": sorted(state.call_edges.values(), key=lambda item: (item["caller"], item["callee"])),
                "coverage": coverage,
                "partial_reason": "; ".join(coverage["notes"]) if coverage["notes"] else None,
            },
        )
    else:
        (audit_dir / ARTIFACT_PATHS["CALL_GRAPH_SKIPPED"]).write_text(
            "# Call Graph Skipped\n\nReason: no statically supported call edges were observed; no full call graph was guessed.\n",
            encoding="utf-8",
        )
    write_architecture(audit_dir / ARTIFACT_PATHS["ARCHITECTURE"], architecture_baseline(module_graph, symbol_index))
    append_centrality_status(audit_dir, algorithm)
