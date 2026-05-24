"""Evidence-backed Obsidian wiki generation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from .audit_canonical_graph import run_canonical_graph_outputs
from .models import ARTIFACT_PATHS


ROOT_PAGES = [
    "wiki/000_home.md",
    "wiki/001_repo_summary.md",
    "wiki/002_architecture_overview.md",
    "wiki/003_reuse_index.md",
    "wiki/004_risk_index.md",
]
WIKI_SOURCE_KEYS = [
    "RUN_CONFIG",
    "FILE_INDEX",
    "EVIDENCE_INDEX",
    "PROVENANCE",
    "MANIFESTS",
    "ARCHITECTURE",
    "MODULE_GRAPH",
    "SYMBOL_INDEX",
    "GRAPH",
    "FEATURE_CATALOG",
    "PATTERNS",
    "SPECIAL_IMPLEMENTATIONS",
    "REUSE_CARDS",
    "REUSE_MAP",
    "RISK_FINDINGS",
    "RISK_REPORT",
    "SUSPICIOUS_BEHAVIORS",
    "OPEN_QUESTIONS",
]
DECISION_MARKER = re.compile(r"\b(adr|architecture decision|decision|decided|rationale)\b", re.IGNORECASE)


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def available_evidence(audit_dir: Path) -> set[str]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    return {str(item.get("id")) for item in evidence.get("evidence", []) if isinstance(item, dict) and item.get("id")}


def evidence_by_path(audit_dir: Path) -> dict[str, list[str]]:
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])
    result: dict[str, list[str]] = {}
    for item in evidence.get("evidence", []):
        if isinstance(item, dict) and item.get("path") and item.get("id"):
            result.setdefault(str(item["path"]), []).append(str(item["id"]))
    return result


def stable_slug(value: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{base[:72]}-{digest}"


def evidence_text(evidence_ids: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in sorted(set(evidence_ids)))


def source_link(audit_dir: Path, page_path: Path, artifact: str) -> str:
    target = audit_dir / artifact
    relative = Path(os.path.relpath(target, page_path.parent)).as_posix()
    return f"[{artifact}]({relative})"


def repo_label(run_config: dict[str, Any] | None = None) -> str:
    repo = (run_config or {}).get("repo") if isinstance((run_config or {}).get("repo"), dict) else {}
    github = repo.get("github") if isinstance(repo.get("github"), dict) else {}
    owner = github.get("owner")
    name = github.get("repo") or github.get("name")
    if owner and name:
        return f"{owner}/{name}"
    return str(repo.get("path") or "local")


def provenance_commit(audit_dir: Path) -> str:
    provenance = load_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"])
    git = provenance.get("git") if isinstance(provenance.get("git"), dict) else {}
    return str(git.get("commit") or "unknown")


def frontmatter(
    audit_dir: Path,
    title: str,
    page_type: str,
    slug: str,
    tags: list[str],
    source_artifacts: list[str],
    evidence_ids: list[str],
    status: str,
    run_config: dict[str, Any] | None = None,
) -> str:
    return "\n".join(
        [
            "---",
            f"title: {json.dumps(title)}",
            f"type: {json.dumps(page_type)}",
            f"repo: {json.dumps(repo_label(run_config))}",
            f"commit: {json.dumps(provenance_commit(audit_dir))}",
            f"slug: {json.dumps(slug)}",
            f"tags: {json.dumps(sorted(set(['agentic-deep-audit', *tags])))}",
            f"source_artifacts: {json.dumps(source_artifacts)}",
            f"evidence_ids: {json.dumps(sorted(set(evidence_ids)))}",
            f"status: {json.dumps(status)}",
            "---",
            "",
        ]
    )


def write_page(
    audit_dir: Path,
    relative_path: str,
    title: str,
    page_type: str,
    tags: list[str],
    source_artifacts: list[str],
    evidence_ids: list[str],
    purpose: str,
    details: list[str],
    open_questions: list[str] | None = None,
    backlinks: list[str] | None = None,
    status: str | None = None,
    run_config: dict[str, Any] | None = None,
) -> None:
    path = audit_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    slug = Path(relative_path).with_suffix("").relative_to("wiki").as_posix()
    effective_status = status or ("observed" if evidence_ids else "skipped")
    lines = [
        frontmatter(audit_dir, title, page_type, slug, tags, source_artifacts, evidence_ids, effective_status, run_config),
        f"# {title}",
        "",
        "## Purpose",
        "",
        purpose,
        "",
        "## Key Evidence",
        "",
    ]
    if evidence_ids:
        lines.append(f"- Evidence: {evidence_text(evidence_ids)}")
    else:
        lines.append("- skipped: no reachable evidence id is available for this page.")
    lines.extend(["", "## Source Artifacts", ""])
    for artifact in source_artifacts:
        if (audit_dir / artifact).exists():
            lines.append(f"- {source_link(audit_dir, path, artifact)}")
        else:
            lines.append(f"- skipped: `{artifact}` is not present.")
    lines.extend(["", "## Details", "", *details, "", "## Open Questions", ""])
    questions = open_questions if open_questions is not None else []
    lines.extend(questions or ["- No page-specific open questions."])
    lines.extend(["", "## Backlinks", ""])
    lines.extend(f"- [[{link}]]" for link in sorted(set(backlinks or ["000_home"])))
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def first_evidence_from(*payloads: dict[str, Any]) -> list[str]:
    for payload in payloads:
        stack: list[Any] = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                ids = value.get("evidence_ids")
                if isinstance(ids, list) and ids:
                    return [str(item) for item in ids if isinstance(item, str)][:3]
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
    return []


def selected_module_nodes(module_graph: dict[str, Any], profile: str) -> list[dict[str, Any]]:
    nodes = [node for node in module_graph.get("nodes", []) if isinstance(node, dict) and node.get("type") == "module"]
    centrality = module_graph.get("centrality") if isinstance(module_graph.get("centrality"), dict) else {}
    if profile == "standard" and centrality:
        def sort_key(node: dict[str, Any]) -> tuple[float, int, str]:
            node_id = str(node.get("id") or "")
            score = centrality.get(node_id) if isinstance(centrality.get(node_id), dict) else {}
            rank = int(score.get("rank") or 999999)
            numeric = float(score.get("score") or 0.0)
            return (-numeric, rank, str(node.get("path") or node_id))

        ordered = sorted(nodes, key=sort_key)
    else:
        ordered = minimal_ranked_nodes(nodes, module_graph)
    if not ordered:
        return []
    if profile == "standard":
        limit = max(1, math.ceil(len(ordered) * 0.2))
    else:
        limit = min(50, math.ceil(len(ordered) * 0.1))
        limit = max(1, limit)
    return ordered[:limit]


def minimal_ranked_nodes(nodes: list[dict[str, Any]], module_graph: dict[str, Any]) -> list[dict[str, Any]]:
    incoming: Counter[str] = Counter()
    outgoing: Counter[str] = Counter()
    for edge in module_graph.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("source") or "")
        target = str(edge.get("target") or "")
        if source:
            outgoing[source] += 1
        if target:
            incoming[target] += 1

    def size(node: dict[str, Any]) -> int:
        value = node.get("size_bytes")
        if value is None:
            value = node.get("size")
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    def sort_key(node: dict[str, Any]) -> tuple[float, int, str]:
        node_id = str(node.get("id") or "")
        path = str(node.get("path") or node_id)
        size_bytes = size(node)
        score = incoming[node_id] + outgoing[node_id] + math.log2(max(size_bytes, 1))
        return (-score, -size_bytes, path)

    return sorted(nodes, key=sort_key)


def module_slug(node: dict[str, Any]) -> str:
    return stable_slug(str(node.get("path") or node.get("label") or node.get("id") or "module"))


def selected_module_slugs(module_graph: dict[str, Any], profile: str) -> set[str]:
    return {module_slug(node) for node in selected_module_nodes(module_graph, profile)}


def write_root_pages(audit_dir: Path, run_config: dict[str, Any]) -> None:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    provenance = load_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"])
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    reuse_cards = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"])
    risk_findings = load_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"])
    evidence = first_evidence_from(file_index, module_graph, reuse_cards, risk_findings)
    repo = file_index.get("repo") if isinstance(file_index.get("repo"), dict) else {}
    write_page(
        audit_dir,
        "wiki/000_home.md",
        "Audit Wiki Home",
        "home",
        ["index"],
        [ARTIFACT_PATHS["RUN_CONFIG"], ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["EVIDENCE_INDEX"]],
        evidence,
        "Entry point for the evidence-backed audit wiki.",
        [
            f"- Profile: `{run_config.get('profile') or 'minimal'}`.",
            f"- Target repo path: `{repo.get('path') or (run_config.get('repo') or {}).get('path') or 'unknown'}`.",
            "- Root sections: [[001_repo_summary]], [[002_architecture_overview]], [[003_reuse_index]], [[004_risk_index]].",
        ],
        run_config=run_config,
        backlinks=[],
    )
    write_page(
        audit_dir,
        "wiki/001_repo_summary.md",
        "Repository Summary",
        "repo_summary",
        ["summary"],
        [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["PROVENANCE"], ARTIFACT_PATHS["MANIFESTS"]],
        first_evidence_from(file_index, provenance),
        "Summarize repository inventory and provenance without executing target code.",
        [f"- Files indexed: `{len(file_index.get('records', []))}`.", f"- Git commit: `{((provenance.get('git') or {}).get('commit') or 'unknown')}`."],
        run_config=run_config,
    )
    write_page(
        audit_dir,
        "wiki/002_architecture_overview.md",
        "Architecture Overview",
        "architecture",
        ["architecture"],
        [ARTIFACT_PATHS["ARCHITECTURE"], ARTIFACT_PATHS["MODULE_GRAPH"], ARTIFACT_PATHS["SYMBOL_INDEX"], ARTIFACT_PATHS["GRAPH"]],
        first_evidence_from(module_graph),
        "Expose architecture, graph and symbol findings as navigable wiki context.",
        [f"- Module nodes: `{len(module_graph.get('nodes', []))}`.", f"- Module edges: `{len(module_graph.get('edges', []))}`.", "- Module pages live under [[modules/index]]."],
        run_config=run_config,
    )
    write_page(
        audit_dir,
        "wiki/003_reuse_index.md",
        "Reuse Index",
        "reuse_index",
        ["reuse"],
        [ARTIFACT_PATHS["REUSE_CARDS"], ARTIFACT_PATHS["REUSE_MAP"], ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"]],
        first_evidence_from(reuse_cards),
        "Index reusable implementation candidates with caveats and human-review gates.",
        [f"- Reuse cards: `{len(reuse_cards.get('cards', []))}`.", "- Detailed pages live under [[reuse/index]]."],
        run_config=run_config,
    )
    write_page(
        audit_dir,
        "wiki/004_risk_index.md",
        "Risk Index",
        "risk_index",
        ["risk"],
        [ARTIFACT_PATHS["RISK_FINDINGS"], ARTIFACT_PATHS["RISK_REPORT"], ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"]],
        first_evidence_from(risk_findings),
        "Index risk, security and supply-chain observations without claiming absence of vulnerabilities.",
        [f"- Risk findings: `{len(risk_findings.get('findings', []))}`.", "- Detailed pages live under [[risks/index]]."],
        run_config=run_config,
    )


def write_module_pages(audit_dir: Path, run_config: dict[str, Any]) -> None:
    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    profile = str(run_config.get("profile") or "minimal")
    nodes = selected_module_nodes(module_graph, profile)
    write_page(audit_dir, "wiki/modules/index.md", "Module Pages", "module_index", ["modules"], [ARTIFACT_PATHS["MODULE_GRAPH"]], first_evidence_from(module_graph), "Index selected top-centrality modules.", [f"- Selected module pages: `{len(nodes)}`."], run_config=run_config)
    for node in nodes:
        slug = module_slug(node)
        path_value = str(node.get("path") or node.get("label") or node.get("id"))
        evidence_ids = [str(item) for item in node.get("evidence_ids", []) if isinstance(item, str)]
        write_page(
            audit_dir,
            f"wiki/modules/{slug}.md",
            f"Module {path_value}",
            "module",
            ["module"],
            [ARTIFACT_PATHS["MODULE_GRAPH"], ARTIFACT_PATHS["SYMBOL_INDEX"], ARTIFACT_PATHS["GRAPH"]],
            evidence_ids,
            "Describe a top-ranked module selected by deterministic centrality ordering.",
            [f"- Node id: `{node.get('id')}`.", f"- Path: `{path_value}`.", f"- Type: `{node.get('type')}`."],
            backlinks=["002_architecture_overview", "modules/index"],
            run_config=run_config,
        )


def table_rows(path: Path) -> list[list[str]]:
    if not path.exists():
        return []
    rows: list[list[str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells and cells[0].lower() not in {"feature", "pattern", ""}:
            rows.append(cells)
    return rows


def write_table_category(audit_dir: Path, run_config: dict[str, Any], artifact_key: str, folder: str, title: str, page_type: str) -> None:
    rows = table_rows(audit_dir / ARTIFACT_PATHS[artifact_key])
    write_page(audit_dir, f"wiki/{folder}/index.md", title, f"{page_type}_index", [folder], [ARTIFACT_PATHS[artifact_key]], first_evidence_from({"rows": rows}), f"Index {folder} pages.", [f"- Page count: `{len(rows)}`."], run_config=run_config)
    if not rows:
        write_page(audit_dir, f"wiki/{folder}/000_{folder}_skipped.md", f"{title} Skipped", page_type, [folder], [ARTIFACT_PATHS[artifact_key]], [], f"No evidence-backed {folder} rows were available.", ["- skipped: source artifact has no promotable rows."], backlinks=[f"{folder}/index"], run_config=run_config)
        return
    for index, cells in enumerate(rows, start=1):
        label = cells[0]
        evidence_ids = re.findall(r"ev-\d{6}", " ".join(cells))
        slug = stable_slug(label)
        write_page(audit_dir, f"wiki/{folder}/{index:03d}_{slug}.md", label, page_type, [folder], [ARTIFACT_PATHS[artifact_key]], evidence_ids, f"Expose `{label}` from `{ARTIFACT_PATHS[artifact_key]}`.", [f"- Source row: `{' | '.join(cells)}`."], backlinks=[f"{folder}/index"], run_config=run_config)


def list_records(payload: dict[str, Any], keys: list[str]) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def write_json_category(audit_dir: Path, run_config: dict[str, Any], artifact_key: str, folder: str, title: str, page_type: str, keys: list[str]) -> None:
    payload = load_json(audit_dir / ARTIFACT_PATHS[artifact_key])
    records = list_records(payload, keys)
    write_page(audit_dir, f"wiki/{folder}/index.md", title, f"{page_type}_index", [folder], [ARTIFACT_PATHS[artifact_key]], first_evidence_from(payload), f"Index {folder} pages.", [f"- Page count: `{len(records)}`."], run_config=run_config)
    if not records:
        write_page(audit_dir, f"wiki/{folder}/000_{folder}_skipped.md", f"{title} Skipped", page_type, [folder], [ARTIFACT_PATHS[artifact_key]], [], f"No evidence-backed {folder} records were available.", ["- skipped: source artifact has no promotable records."], backlinks=[f"{folder}/index"], run_config=run_config)
        return
    for index, record in enumerate(records, start=1):
        label = str(record.get("name") or record.get("title") or record.get("candidate_id") or record.get("risk_id") or record.get("id") or f"{page_type}-{index}")
        evidence_ids = [str(item) for item in record.get("evidence_ids", []) if isinstance(item, str)]
        slug = stable_slug(label)
        write_page(audit_dir, f"wiki/{folder}/{index:03d}_{slug}.md", label, page_type, [folder], [ARTIFACT_PATHS[artifact_key]], evidence_ids, f"Expose `{label}` from `{ARTIFACT_PATHS[artifact_key]}`.", [f"- Source record id: `{record.get('candidate_id') or record.get('risk_id') or record.get('id') or index}`.", f"- Status: `{record.get('decision') or record.get('severity') or record.get('status') or 'observed'}`."], backlinks=[f"{folder}/index"], run_config=run_config)


def decision_paths(audit_dir: Path) -> list[tuple[str, list[str]]]:
    file_index = load_json(audit_dir / ARTIFACT_PATHS["FILE_INDEX"])
    repo_path = Path(str((file_index.get("repo") or {}).get("path") or "."))
    evidence = evidence_by_path(audit_dir)
    results: list[tuple[str, list[str]]] = []
    for record in file_index.get("records", []):
        if not isinstance(record, dict):
            continue
        path_value = str(record.get("path_normalized") or record.get("path") or "")
        name = Path(path_value).name.lower()
        marker_path = repo_path / path_value
        marker = False
        if path_value.lower().startswith("docs/decisions/") or "adr" in name or "decision" in name or name == "architecture.md":
            marker = True
        elif name == "changelog.md" and marker_path.exists():
            marker = bool(DECISION_MARKER.search(marker_path.read_text(encoding="utf-8", errors="replace")))
        if marker:
            results.append((path_value, evidence.get(path_value, [])))
    return sorted(results, key=lambda item: item[0])


def write_decision_pages(audit_dir: Path, run_config: dict[str, Any]) -> None:
    decisions = decision_paths(audit_dir)
    write_page(audit_dir, "wiki/decisions/index.md", "Decision Pages", "decision_index", ["decisions"], [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["OPEN_QUESTIONS"]], [], "Index documented architecture decisions and decision-like docs.", [f"- Decision pages: `{len(decisions)}`."], run_config=run_config)
    if not decisions:
        write_page(audit_dir, "wiki/decisions/000_decisions_skipped.md", "Decision Docs Skipped", "decision", ["decisions"], [ARTIFACT_PATHS["FILE_INDEX"], ARTIFACT_PATHS["OPEN_QUESTIONS"]], [], "No ADR or decision document was found.", ["- skipped: no ADR, docs/decisions file, changelog decision marker or architecture doc found."], backlinks=["decisions/index"], run_config=run_config)
        return
    for index, (path_value, evidence_ids) in enumerate(decisions, start=1):
        slug = stable_slug(path_value)
        write_page(audit_dir, f"wiki/decisions/{index:03d}_{slug}.md", f"Decision {path_value}", "decision", ["decisions"], [ARTIFACT_PATHS["FILE_INDEX"]], evidence_ids, "Capture a documented architecture decision source.", [f"- Source path: `{path_value}`."], backlinks=["decisions/index"], run_config=run_config)


def run_wiki(run_config: dict[str, Any], audit_dir: Path) -> None:
    wiki_dir = audit_dir / "wiki"
    if wiki_dir.exists():
        shutil.rmtree(wiki_dir)
    write_root_pages(audit_dir, run_config)
    write_module_pages(audit_dir, run_config)
    write_table_category(audit_dir, run_config, "FEATURE_CATALOG", "features", "Feature Pages", "feature")
    write_table_category(audit_dir, run_config, "PATTERNS", "patterns", "Pattern Pages", "pattern")
    write_json_category(audit_dir, run_config, "RISK_FINDINGS", "risks", "Risk Pages", "risk", ["findings", "records", "risks"])
    write_json_category(audit_dir, run_config, "REUSE_CARDS", "reuse", "Reuse Pages", "reuse", ["cards"])
    write_decision_pages(audit_dir, run_config)
    if (audit_dir / ARTIFACT_PATHS["GRAPH"]).exists():
        run_canonical_graph_outputs(run_config, audit_dir)
