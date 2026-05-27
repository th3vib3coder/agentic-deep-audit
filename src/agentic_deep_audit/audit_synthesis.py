"""Evidence-backed architecture, feature and pattern synthesis."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .audit_canonical_graph import run_canonical_graph_outputs
from .models import ARTIFACT_PATHS


MARKDOWN_INVISIBLE_CHARS = "\u00ad\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2066\u2067\u2068\u2069\ufeff"
MAX_ARCHITECTURE_BYTES = 2_000_000
MAX_DECISION_DOC_BYTES = 1_000_000


READ_ONLY_HANDOFF_INPUTS = [
    ARTIFACT_PATHS["MODULE_GRAPH"],
    ARTIFACT_PATHS["SYMBOL_INDEX"],
    ARTIFACT_PATHS["API_SURFACE"],
    ARTIFACT_PATHS["CLI_SURFACE"],
    ARTIFACT_PATHS["MCP_SURFACE"],
    ARTIFACT_PATHS["CONFIG_SURFACE"],
    ARTIFACT_PATHS["MANIFESTS"],
    ARTIFACT_PATHS["EVIDENCE_INDEX"],
]


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_optional_json(audit_dir: Path, artifact_key: str) -> dict[str, Any]:
    path = audit_dir / ARTIFACT_PATHS[artifact_key]
    if not path.exists():
        return {}
    return load_json(path)


def evidence_ids_available(audit_dir: Path) -> set[str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def evidence_by_path(audit_dir: Path) -> dict[str, str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("path")): str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("path") and item.get("id")}


def has_reachable_evidence(item: dict[str, Any], available: set[str]) -> bool:
    ids = item.get("evidence_ids")
    return isinstance(ids, list) and bool(ids) and all(isinstance(evidence_id, str) and evidence_id in available for evidence_id in ids)


def ev(ids: list[str]) -> str:
    return ", ".join(f"`{evidence_id}`" for evidence_id in sorted(set(ids)))


def clean_text(value: Any, max_chars: int = 300) -> str:
    text = str(value or "")
    text = "".join(char for char in text if char not in MARKDOWN_INVISIBLE_CHARS and not (0xE0000 <= ord(char) <= 0xE007F))
    text = "".join(char for char in text if char in {"\n", "\t"} or ord(char) >= 32)
    return text[:max_chars]


def markdown_cell(value: Any, max_chars: int = 300) -> str:
    return re.sub(r"\s+", " ", clean_text(value, max_chars)).strip().replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def section_bounds(text: str, heading: str) -> tuple[int, int] | None:
    if len(text.encode("utf-8")) > MAX_ARCHITECTURE_BYTES:
        text = text.encode("utf-8")[:MAX_ARCHITECTURE_BYTES].decode("utf-8", errors="ignore")
    offset = 0
    start: int | None = None
    content_end: int | None = None
    for line in text.splitlines(keepends=True):
        stripped = line.rstrip("\r\n")
        if start is None and stripped == heading:
            start = offset
        elif start is not None and stripped.startswith("## ") and stripped != heading:
            return start, content_end if content_end is not None else offset
        elif start is not None and stripped:
            content_end = offset + len(line)
        offset += len(line)
    return (start, len(text)) if start is not None else None


def baseline_section(text: str) -> str:
    bounds = section_bounds(text, "## Baseline")
    if bounds is None:
        return ""
    start, end = bounds
    return text[start:end]


def enrich_architecture(audit_dir: Path, module_graph: dict[str, Any], symbol_index: dict[str, Any], surfaces: dict[str, dict[str, Any]]) -> None:
    path = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    original = path.read_text(encoding="utf-8") if path.exists() and path.stat().st_size <= MAX_ARCHITECTURE_BYTES else "# Architecture\n\n## Baseline\n\n- No baseline graph data available.\n"
    baseline_bounds = section_bounds(original, "## Baseline")
    baseline = baseline_section(original) or "## Baseline\n\n- No baseline graph data available.\n"
    module_count = len(module_graph.get("nodes", []))
    edge_count = len(module_graph.get("edges", []))
    symbol_count = len(symbol_index.get("symbols", []))
    api_count = len((surfaces.get("API_SURFACE") or {}).get("records", []))
    cli_count = len((surfaces.get("CLI_SURFACE") or {}).get("records", []))
    config_count = len((surfaces.get("CONFIG_SURFACE") or {}).get("records", []))
    mcp_count = len((surfaces.get("MCP_SURFACE") or {}).get("records", []))
    evidence = first_evidence(module_graph, symbol_index, surfaces)
    if evidence:
        evidence_text = ev(evidence)
        synthesis = [
            "## Evidence-Backed Synthesis",
            "",
            "### Layers",
            "",
            f"- Static graph layer: {module_count} modules and {edge_count} dependency edges. Evidence: {evidence_text}",
            f"- Public surface layer: {api_count} API, {cli_count} CLI, {config_count} config and {mcp_count} MCP records. Evidence: {evidence_text}",
            "",
            "### Boundaries",
            "",
            f"- Boundaries are inferred only from graph and surface artifacts generated in this audit. Evidence: {evidence_text}",
            "",
            "### Dependency Direction",
            "",
            f"- Dependency direction follows `MODULE_GRAPH.json` edge source-to-target orientation. Evidence: {evidence_text}",
            "",
            "### Cycles",
            "",
            f"- Cycle detection is not yet claimed; unresolved cycle analysis remains in open questions if needed. Evidence: {evidence_text}",
            "",
            "### Observability",
            "",
            f"- Observability claims are limited to discovered config, env and CLI surfaces. Evidence: {evidence_text}",
            "",
            "### Concurrency",
            "",
            f"- Concurrency claims are not inferred without explicit code evidence. Evidence: {evidence_text}",
            "",
            "### Caching",
            "",
            f"- Caching claims are not inferred without explicit code evidence. Evidence: {evidence_text}",
            "",
        ]
    else:
        synthesis = [
            "## Evidence-Backed Synthesis",
            "",
            "- skipped: no reachable graph, symbol or surface evidence for architecture synthesis.",
            "",
        ]
    prefix = original[: baseline_bounds[0]] if baseline_bounds is not None else "# Architecture\n\n"
    separator = "\n" if baseline.endswith("\n") else "\n\n"
    atomic_write_text(path, prefix + baseline + separator + "\n".join(synthesis))


def first_evidence(module_graph: dict[str, Any], symbol_index: dict[str, Any], surfaces: dict[str, dict[str, Any]]) -> list[str]:
    for source in [module_graph.get("nodes", []), module_graph.get("edges", []), symbol_index.get("symbols", [])]:
        for item in source:
            if isinstance(item, dict) and item.get("evidence_ids"):
                return list(item["evidence_ids"])[:2]
    for payload in surfaces.values():
        for item in payload.get("records", []):
            if isinstance(item, dict) and item.get("evidence_ids"):
                return list(item["evidence_ids"])[:2]
    return []


def build_feature_catalog(audit_dir: Path, surfaces: dict[str, dict[str, Any]], symbol_index: dict[str, Any], file_index: dict[str, Any], available: set[str]) -> list[str]:
    lines = ["# Feature Catalog", "", "| Feature | Source | Status | Evidence |", "|---|---|---|---|"]
    open_questions: list[str] = []
    count = 0
    evidence_lookup = evidence_by_path(audit_dir)
    for artifact_key, payload in sorted(surfaces.items()):
        for record in payload.get("records", []):
            if not isinstance(record, dict):
                continue
            label = markdown_cell(record.get("path") or record.get("name") or record.get("command") or record.get("kind"))
            source = markdown_cell(f"{artifact_key}:{record.get('source_path')}")
            status = markdown_cell(record.get("status"))
            if has_reachable_evidence(record, available):
                count += 1
                lines.append(f"| {label} | {source} | {status} | {ev(record['evidence_ids'])} |")
            else:
                open_questions.append(f"- Surface `{artifact_key}:{record.get('surface_id')}` lacks reachable evidence and was not promoted to feature.")
    for symbol in symbol_index.get("symbols", []):
        if not isinstance(symbol, dict):
            continue
        if symbol.get("public") is True and has_reachable_evidence(symbol, available):
            count += 1
            source = markdown_cell(f"SYMBOL_INDEX:{symbol.get('path')}")
            lines.append(f"| {markdown_cell(symbol.get('name'))} | {source} | observed | {ev(symbol['evidence_ids'])} |")
        elif symbol.get("public") is True:
            open_questions.append(f"- Public symbol `{symbol.get('name')}` lacks reachable evidence.")
    for doc in file_index.get("root_documents", []):
        if not isinstance(doc, dict) or doc.get("status") != "found" or not doc.get("path"):
            continue
        evidence_id = evidence_lookup.get(str(doc["path"]))
        if evidence_id in available:
            count += 1
            source = markdown_cell(f"FILE_INDEX.root_documents:{doc['path']}")
            lines.append(f"| Root document {markdown_cell(doc.get('name'))} | {source} | observed | {ev([evidence_id])} |")
        else:
            open_questions.append(f"- Root document `{doc.get('path')}` lacks reachable evidence and was not promoted to feature.")
    if count == 0:
        lines.append("|  | skipped | skipped |  |")
        open_questions.append("- No evidence-backed features were found.")
    atomic_write_text(audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"], "\n".join(lines) + "\n")
    return open_questions


def build_patterns(audit_dir: Path, module_graph: dict[str, Any], surfaces: dict[str, dict[str, Any]], available: set[str]) -> None:
    rows: list[str] = ["# Patterns", "", "| Pattern | Implementation Loci | Confidence | Reuse Relevance | Evidence |", "|---|---|---|---|---|"]
    edges = [edge for edge in module_graph.get("edges", []) if isinstance(edge, dict) and has_reachable_evidence(edge, available)]
    if edges:
        evidence = list(edges[0]["evidence_ids"])
        rows.append(f"| Dependency-oriented module split | MODULE_GRAPH imports edges | medium | map reusable module boundaries | {ev(evidence)} |")
    for record in (surfaces.get("API_SURFACE") or {}).get("records", []):
        if isinstance(record, dict) and has_reachable_evidence(record, available):
            rows.append(f"| Public API endpoint | {markdown_cell(record.get('source_path'))} | {markdown_cell(record.get('confidence'))} | integration surface | {ev(record['evidence_ids'])} |")
            break
    if len(rows) == 4:
        rows.append("| skipped | no evidence-backed pattern | low | none |  |")
    atomic_write_text(audit_dir / ARTIFACT_PATHS["PATTERNS"], "\n".join(rows) + "\n")


def license_status_source(audit_dir: Path, available: set[str]) -> str:
    evidence_index = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    for item in evidence_index.get("evidence", []):
        if isinstance(item, dict) and str(item.get("path", "")).upper().startswith("LICENSE") and item.get("id") in available:
            return f"root_license:{item['id']}"
    return "unknown_requires_license_card"


def build_special_implementations(audit_dir: Path, symbol_index: dict[str, Any], module_graph: dict[str, Any], available: set[str]) -> None:
    candidates: list[dict[str, Any]] = []
    license_source = license_status_source(audit_dir, available)
    dependencies_by_file: dict[str, set[str]] = {}
    for edge in module_graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source", "")).removeprefix("module:")
        target = str(edge.get("target", ""))
        dependencies_by_file.setdefault(source, set()).add(target)
    for symbol in symbol_index.get("symbols", []):
        if not isinstance(symbol, dict) or symbol.get("kind") not in {"function", "class", "method"}:
            continue
        if not has_reachable_evidence(symbol, available):
            continue
        name = clean_text(symbol.get("name"))
        path = clean_text(symbol.get("path"))
        candidates.append(
            {
                "candidate_id": f"reuse-{len(candidates) + 1:06d}",
                "name": name,
                "kind": "reusable_component",
                "files": [path],
                "coupling": "medium" if dependencies_by_file.get(path) else "low",
                "dependencies": [clean_text(item) for item in sorted(dependencies_by_file.get(path, set()))],
                "license_status_source": license_source,
                "performance_note": "No benchmark evidence collected in phase 5; performance review is deferred to phase 20.",
                "limitations": ["static synthesis only", "requires human review before reuse"],
                "evidence_ids": list(symbol["evidence_ids"]),
            }
        )
        if len(candidates) >= 20:
            break
    write_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"], {"schema_version": "1.0", "run_id": load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).get("run_id"), "candidates": candidates, "skipped": not candidates, "skip_reason": None if candidates else "no evidence-backed reusable component candidates"})


def resolve_repo_relative_file(repo_path: Path, path_value: str) -> Path | None:
    if not path_value or "\\" in path_value or ":" in path_value or "\x00" in path_value:
        return None
    posix = PurePosixPath(path_value)
    windows = PureWindowsPath(path_value)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        return None
    if ".." in posix.parts or ".." in windows.parts:
        return None
    root = repo_path.resolve()
    candidate = (root / path_value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def changelog_has_decision_marker(repo_path: Path, path_value: str) -> bool:
    try:
        source = resolve_repo_relative_file(repo_path, path_value)
        if source is None or source.stat().st_size > MAX_DECISION_DOC_BYTES:
            return False
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"\b(adr|architecture decision|decision|decided|rationale)\b", text, flags=re.IGNORECASE))


def decision_doc_questions(audit_dir: Path) -> list[str]:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or "."))
    records = [
        str(record.get("path_normalized") or record.get("path") or "")
        for record in file_index.get("records", [])
        if isinstance(record, dict) and resolve_repo_relative_file(repo_path, str(record.get("path_normalized") or record.get("path") or "")) is not None
    ]
    decision_paths = [
        path
        for path in records
        if path.lower().startswith("docs/decisions/")
        or "adr" in Path(path).name.lower()
        or "decision" in Path(path).name.lower()
        or Path(path).name.lower() == "architecture.md"
        or (Path(path).name.lower() == "changelog.md" and changelog_has_decision_marker(repo_path, path))
    ]
    if decision_paths:
        return []
    return ["- Decision docs scan skipped: no ADR, `docs/decisions/*`, changelog decision marker or architecture doc found."]


def write_open_questions(audit_dir: Path, questions: list[str]) -> None:
    lines = ["# Open Questions", ""]
    if questions:
        lines.extend(questions)
    else:
        lines.append("- No synthesis open questions.")
    lines.append("")
    atomic_write_text(audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"], "\n".join(lines))


def run_synthesis(run_config: dict[str, Any], audit_dir: Path) -> None:
    module_graph = load_optional_json(audit_dir, "MODULE_GRAPH")
    symbol_index = load_optional_json(audit_dir, "SYMBOL_INDEX")
    file_index = load_optional_json(audit_dir, "FILE_INDEX")
    surfaces = {key: load_optional_json(audit_dir, key) for key in ["API_SURFACE", "CLI_SURFACE", "MCP_SURFACE", "CONFIG_SURFACE"]}
    available = evidence_ids_available(audit_dir)
    enrich_architecture(audit_dir, module_graph, symbol_index, surfaces)
    questions = build_feature_catalog(audit_dir, surfaces, symbol_index, file_index, available)
    build_patterns(audit_dir, module_graph, surfaces, available)
    build_special_implementations(audit_dir, symbol_index, module_graph, available)
    questions.extend(decision_doc_questions(audit_dir))
    write_open_questions(audit_dir, questions)
    if (audit_dir / ARTIFACT_PATHS["GRAPH"]).exists():
        run_canonical_graph_outputs(run_config, audit_dir)
