"""Regression tests for the 4 graph-validation blocker classes that withheld REPORT.md on
nousresearch/hermes-agent (2026-06-03). Each test reproduces one class and pins the fixed behaviour.

A: accumulated conditional edge weight (B03 sums per-site 0.5s) must NOT be flagged non-conservative.
B1: a canonical wiki node's evidence comes from the DECLARED frontmatter, not a coincidental slug substring.
B2: validate_page must ignore ev-NNNNNN substrings inside slugs/link-targets but still catch prose citations.
C: a dynamic-import edge target (package:<dynamic>) must be materialised as a node so the edge isn't dropped.
D: anti-overclaim must skip absolute language inside QUOTED target excerpts but still flag the audit's own claims.
"""

from __future__ import annotations

import json
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS
from agentic_deep_audit.audit_validate import validate_graph_artifacts
from agentic_deep_audit.audit_canonical_graph import add_markdown_concept_nodes, add_module_and_symbol_nodes, add_wiki_nodes
from agentic_deep_audit.validate_wiki import validate_page
from agentic_deep_audit.validate_claim_language import validate_anti_overclaim_language


def _write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = payload if isinstance(payload, str) else (json.dumps(payload, indent=2) + "\n")
    path.write_text(text, encoding="utf-8")


_PAGE = (
    "---\n"
    'title: "Feature X"\n'
    'type: "feature"\n'
    'repo: "/tmp/repo"\n'
    'commit: "0123456789abcdef0123456789abcdef01234567"\n'
    'slug: "{slug}"\n'
    'tags: ["agentic-deep-audit", "features"]\n'
    'source_artifacts: ["FEATURE_CATALOG.md"]\n'
    'evidence_ids: {evidence}\n'
    'status: "observed"\n'
    "---\n\n# Feature X\n\n{body}\n"
)


def test_accumulated_conditional_edge_weight_not_flagged_non_conservative(tmp_path: Path) -> None:
    audit = tmp_path / "audit"
    audit.mkdir()
    module_graph = {
        "schema_version": "1.0",
        "nodes": [
            {"id": "module:a.py", "type": "module", "path": "a.py", "evidence_ids": ["ev-000001"]},
            {"id": "module:b.py", "type": "module", "path": "b.py", "evidence_ids": ["ev-000001"]},
        ],
        # a module imported conditionally 3x -> B03 accumulates per-site 0.5 to 1.5; legitimate, not a defect.
        "edges": [{
            "source": "module:a.py", "target": "module:b.py", "type": "imports",
            "weight": 1.5, "conditional": True, "dynamic": False, "evidence_ids": ["ev-000001"],
        }],
        "centrality": {"module:a.py": {"algorithm": "weighted_in_degree", "score": 0.0}},
    }
    _write(audit / ARTIFACT_PATHS["MODULE_GRAPH"], module_graph)
    _write(audit / ARTIFACT_PATHS["SYMBOL_INDEX"], {"symbols": []})
    _write(audit / ARTIFACT_PATHS["RUN_CONFIG"], {"schema_version": "1.0"})
    result = validate_graph_artifacts(audit)
    assert not any("non-conservative weight" in e for e in result.errors), result.errors


def test_dynamic_import_edge_target_is_materialised_as_node(tmp_path: Path) -> None:
    module_graph = {
        "nodes": [{"id": "module:a.py", "type": "module", "path": "a.py", "evidence_ids": ["ev-000001"]}],
        "edges": [{
            "source": "module:a.py", "target": "package:<dynamic>", "type": "imports",
            "weight": 0.5, "conditional": True, "dynamic": True, "evidence_ids": ["ev-000001"],
        }],
        "centrality": {},
    }
    nodes: dict = {}
    edges: dict = {}
    add_module_and_symbol_nodes(nodes, edges, module_graph, {"symbols": []}, set())
    assert "package:<dynamic>" in nodes, "dynamic-import target was not materialised as a node"
    assert ("module:a.py", "package:<dynamic>", "depends_on") in edges


def test_canonical_wiki_node_evidence_from_frontmatter_not_slug_substring(tmp_path: Path) -> None:
    audit = tmp_path / "audit"
    page = audit / "wiki" / "features" / "feat-applies-ev-28563836.md"
    _write(page, _PAGE.format(slug="features/feat-applies-ev-28563836",
                              evidence='["ev-000001"]', body="Documents Feature X."))
    nodes: dict = {}
    edges: dict = {}
    add_wiki_nodes(audit, nodes, edges, set())
    wiki_nodes = [n for n in nodes.values() if n.get("artifact_kind") == "wiki_page"]
    assert wiki_nodes, "no wiki_page node built"
    evidence = wiki_nodes[0]["evidence_ids"]
    assert "ev-28563836" not in evidence, f"phantom slug substring harvested: {evidence}"
    assert "ev-000001" in evidence, evidence


def test_validate_page_ignores_slug_and_link_ev_substrings_but_catches_prose(tmp_path: Path) -> None:
    audit = tmp_path / "audit"
    page = audit / "wiki" / "features" / "feat-applies-ev-28563836.md"
    _write(page, _PAGE.format(slug="features/feat-applies-ev-28563836", evidence='["ev-000001"]',
                              body="See [other](features/other-applies-ev-28563836.md)."))
    errors: list[str] = []
    validate_page(audit, page, {"ev-000001"}, set(), errors)
    assert not any("unreachable evidence id: ev-28563836" in e for e in errors), errors

    page2 = audit / "wiki" / "features" / "feat2.md"
    _write(page2, _PAGE.format(slug="features/feat2", evidence='["ev-000001"]',
                               body="This claim cites ev-999999 inline in prose."))
    errors2: list[str] = []
    validate_page(audit, page2, {"ev-000001"}, set(), errors2)
    assert any("unreachable evidence id: ev-999999" in e for e in errors2), errors2

    # REDIRECT note (Codex packet 108): a reference-style link definition target with an ev-substring must
    # also be ignored (not mis-read as a dangling evidence citation) -- same class as the inline-link strip.
    page3 = audit / "wiki" / "features" / "feat3.md"
    _write(page3, _PAGE.format(slug="features/feat3", evidence='["ev-000001"]',
                               body="See the doc below.\n\n[ref]: features/other-applies-ev-28563836.md\n"))
    errors3: list[str] = []
    validate_page(audit, page3, {"ev-000001"}, set(), errors3)
    assert not any("unreachable evidence id: ev-28563836" in e for e in errors3), errors3


def test_anti_overclaim_skips_quoted_excerpts_but_flags_audit_claims(tmp_path: Path) -> None:
    audit = tmp_path / "audit"
    audit.mkdir()
    # a quoted target excerpt (markdown `>` inside an evidence table cell) -- the TARGET's words, not ours.
    _write(audit / ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
           "# Performance Review\n\n"
           "| path | line | status | ev | excerpt |\n"
           "|---|---|---|---|---|\n"
           "| `s.md` | 1 | claim-only:pass | ev-000001 | > Frame-perfect sync with guaranteed zero latency. |\n")
    assert not any("PERFORMANCE_REVIEW" in e for e in validate_anti_overclaim_language(audit))

    # the audit's OWN unscoped absolute claim is still flagged.
    _write(audit / ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
           "# Performance Review\n\nThis tool is perfect and guaranteed for every repository.\n")
    assert any("PERFORMANCE_REVIEW" in e for e in validate_anti_overclaim_language(audit))
    # HARDENING (swarm): an audit claim in a PROSE blockquote (REPORT.md is agent-authored) is STILL flagged.
    _write(audit / ARTIFACT_PATHS["REPORT"], "# Report\n\n> This audit is perfect and guaranteed.\n")
    assert any(e.startswith("anti_overclaim: REPORT.md:") for e in validate_anti_overclaim_language(audit))
    # HARDENING (swarm): a table row mixing a quoted cell with an audit claim in ANOTHER cell -> claim flagged.
    _write(audit / ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
           "# Performance Review\n\n| metric | excerpt | verdict |\n|---|---|---|\n"
           "| latency | > 5ms target quote | perfect and guaranteed throughput |\n")
    assert any("PERFORMANCE_REVIEW" in e for e in validate_anti_overclaim_language(audit))
    # REDIRECT (Codex packet 108): a scope qualifier INSIDE a quoted target cell must NOT suppress an unscoped
    # audit claim in another cell of the same row (scope check must run on the post-strip content).
    _write(audit / ARTIFACT_PATHS["PERFORMANCE_REVIEW"],
           "# Performance Review\n\n| excerpt | verdict |\n|---|---|\n"
           "| > within the analyzed target scope excerpt | perfect and guaranteed throughput |\n")
    assert any("PERFORMANCE_REVIEW" in e for e in validate_anti_overclaim_language(audit))


def test_negative_or_nonfinite_edge_weight_is_flagged(tmp_path: Path) -> None:
    # HARDENING (swarm): Fix A removed the conditional-weight cap; the replacement invariant is that EVERY
    # edge weight is a finite non-negative number (catches NaN/Inf/negative from a builder regression that
    # would silently corrupt centrality/PageRank), without false-positiving on legitimate accumulated weights.
    audit = tmp_path / "audit"
    audit.mkdir()
    module_graph = {
        "schema_version": "1.0",
        "nodes": [{"id": "module:a.py", "type": "module", "path": "a.py", "evidence_ids": ["ev-000001"]}],
        "edges": [{"source": "module:a.py", "target": "module:b.py", "type": "imports",
                   "weight": -3.0, "conditional": False, "dynamic": False, "evidence_ids": ["ev-000001"]}],
        "centrality": {},
    }
    _write(audit / ARTIFACT_PATHS["MODULE_GRAPH"], module_graph)
    _write(audit / ARTIFACT_PATHS["SYMBOL_INDEX"], {"symbols": []})
    _write(audit / ARTIFACT_PATHS["RUN_CONFIG"], {"schema_version": "1.0"})
    result = validate_graph_artifacts(audit)
    assert any("weight must be a finite non-negative number" in e for e in result.errors), result.errors


def test_concept_node_evidence_filters_phantom_path_substring(tmp_path: Path) -> None:
    # HARDENING (swarm follow-up): a coincidental ev-NNNNNN substring in a PATH cell of a FEATURE_CATALOG /
    # PATTERNS row (e.g. a dir `dev-123456/`) must NOT be harvested as a phantom evidence id -- same bug class
    # as the wiki-slug phantom (Fix B). The real declared evidence (`ev-000001`) is retained.
    audit = tmp_path / "audit"
    _write(audit / ARTIFACT_PATHS["EVIDENCE_INDEX"], {"evidence": [{"id": "ev-000001"}]})
    _write(audit / ARTIFACT_PATHS["FEATURE_CATALOG"],
           "# Feature Catalog\n\n| Feature | Path | Evidence |\n|---|---|---|\n"
           "| ParseConfig | src/dev-123456/config.py | `ev-000001` |\n")
    nodes: dict = {}
    edges: dict = {}
    add_markdown_concept_nodes(audit, nodes, edges, set())
    feature_nodes = [n for n in nodes.values() if n.get("type") == "feature"]
    assert feature_nodes, "no feature node built"
    evidence = feature_nodes[0]["evidence_ids"]
    assert "ev-123456" not in evidence, f"phantom path substring harvested: {evidence}"
    assert "ev-000001" in evidence, evidence


def test_dynamic_node_unions_evidence_and_uses_package_kind(tmp_path: Path) -> None:
    # MINOR (swarm [LOW]/[NIT]): multiple edges to the materialised package:<dynamic> node must UNION their
    # evidence (not keep only the first edge's), and a package:* target gets artifact_kind "package".
    module_graph = {
        "nodes": [
            {"id": "module:a.py", "type": "module", "path": "a.py", "evidence_ids": ["ev-000001"]},
            {"id": "module:b.py", "type": "module", "path": "b.py", "evidence_ids": ["ev-000002"]},
        ],
        "edges": [
            {"source": "module:a.py", "target": "package:<dynamic>", "type": "imports",
             "weight": 0.5, "conditional": True, "dynamic": True, "evidence_ids": ["ev-000001"]},
            {"source": "module:b.py", "target": "package:<dynamic>", "type": "imports",
             "weight": 0.5, "conditional": True, "dynamic": True, "evidence_ids": ["ev-000002"]},
        ],
        "centrality": {},
    }
    nodes: dict = {}
    edges: dict = {}
    add_module_and_symbol_nodes(nodes, edges, module_graph, {"symbols": []}, set())
    dyn = nodes["package:<dynamic>"]
    assert dyn["evidence_ids"] == ["ev-000001", "ev-000002"], dyn
    assert dyn.get("artifact_kind") == "package", dyn


def test_frontmatter_evidence_helper_is_single_source_of_truth() -> None:
    # MINOR (swarm [LOW]): the two former byte-duplicate readers now delegate to one shared helper.
    from agentic_deep_audit.wiki_frontmatter import frontmatter_evidence_ids
    from agentic_deep_audit.audit_canonical_graph import wiki_frontmatter_evidence_ids
    from agentic_deep_audit.audit_corpus import trusted_wiki_evidence_ids
    # body mentions ev-999999 + a slug substring ev-123456; only the DECLARED frontmatter ids are returned.
    text = '---\nevidence_ids: ["ev-000002", "ev-000001"]\n---\n\n# x\n\nbody ev-999999, slug feat-ev-123456.\n'
    expected = ["ev-000001", "ev-000002"]
    assert frontmatter_evidence_ids(text) == expected
    assert wiki_frontmatter_evidence_ids(text) == expected
    assert trusted_wiki_evidence_ids(text) == expected
