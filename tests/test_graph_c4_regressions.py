"""C4 graph-layer regression tests.

Each test fails if the corresponding C4 fix is reverted (T5 BLOCKER references in comments).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentic_deep_audit import audit_canonical_graph as acg
from agentic_deep_audit import audit_graph as ag
from agentic_deep_audit.models import ARTIFACT_PATHS
from agentic_deep_audit.validate_canonical_graph import recompose_mismatch_sample, validate_canonical_graph_artifacts


def make_state() -> ag.GraphState:
    return ag.GraphState(repo_path=Path("."), records=[], evidence_by_path={})


# --- Cluster 1: centrality --------------------------------------------------

def test_b04_self_loop_edge_is_not_created_and_is_noted() -> None:
    state = make_state()
    ag.add_edge(state, "module:a", "module:a", "imports", 1.0, False, False, [])
    assert state.edges == {}
    assert any("self-referential" in note for note in state.coverage_notes)


def test_b04_self_loop_does_not_inflate_centrality() -> None:
    nodes = [{"id": "module:a", "type": "module"}]
    edges = [{"source": "module:a", "target": "module:a", "weight": 5.0}]
    result = ag.compute_centrality(nodes, edges, "weighted_in_degree")
    assert result["module:a"]["score"] == 0.0


def test_b03_distinct_import_sites_accumulate_weight() -> None:
    state = make_state()
    # one normal import (1.0) plus two conditional imports (0.5 each) of the same target.
    ag.add_edge(state, "module:a", "module:b", "imports", 1.0, False, False, [])
    ag.add_edge(state, "module:a", "module:b", "imports", 0.5, True, False, [])
    ag.add_edge(state, "module:a", "module:b", "imports", 0.5, True, False, [])
    total = sum(edge["weight"] for edge in state.edges.values())
    assert total == 2.0  # would be 1.5 if the second conditional import were deduped


def test_b03_canonical_duplicate_edges_accumulate_weight_and_flags() -> None:
    edges: dict[tuple[str, str, str], dict] = {}
    acg.add_edge(edges, "module:a", "module:b", "depends_on", [], weight=1.0, conditional=False, dynamic=False)
    acg.add_edge(edges, "module:a", "module:b", "depends_on", [], weight=0.5, conditional=True, dynamic=False)
    acg.add_edge(edges, "module:a", "module:b", "depends_on", [], weight=0.25, conditional=False, dynamic=True)
    edge = edges[("module:a", "module:b", "depends_on")]
    assert edge["weight"] == 1.75
    assert edge["conditional"] is True
    assert edge["dynamic"] is True


def test_b10_pagerank_redistributes_dangling_mass_and_conserves_total() -> None:
    ids = ["module:a", "module:b", "module:c"]
    edges = [{"source": "module:a", "target": "module:b", "weight": 1.0}]
    scores = ag.pagerank(ids, edges)
    assert abs(sum(scores.values()) - 1.0) < 1e-6  # dangling mass preserved, not leaked
    # b receives a's directed flow plus its dangling share; c (pure dangling) only the share.
    assert scores["module:b"] > scores["module:c"]


def test_b10_pagerank_all_dangling_converges_to_uniform() -> None:
    ids = ["module:a", "module:b"]
    scores = ag.pagerank(ids, [])
    assert abs(scores["module:a"] - 0.5) < 1e-6
    assert abs(scores["module:b"] - 0.5) < 1e-6


# --- Cluster 5: JS parser ---------------------------------------------------

def test_b05_js_import_inside_for_loop_is_conditional(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.js").write_text("for (const x of items) {\n  require('./dep');\n}\n", encoding="utf-8")
    state = ag.GraphState(repo_path=repo, records=[], evidence_by_path={})
    ag.parse_js_ts(state, "src/app.js")
    import_edges = [edge for edge in state.edges.values() if edge["type"] == "imports"]
    # without the fix, `for (` is not a conditional opener and the import is flagged unconditional.
    assert import_edges and all(edge["conditional"] for edge in import_edges)
    assert any("heuristic" in note for note in state.coverage_notes)


def test_b05_js_import_inside_plain_else_block_is_conditional(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.js").write_text("if (flag) {\n  require('./a');\n} else {\n  require('./b');\n}\n", encoding="utf-8")
    (repo / "src" / "a.js").write_text("export const a = 1;\n", encoding="utf-8")
    (repo / "src" / "b.js").write_text("export const b = 1;\n", encoding="utf-8")
    state = ag.GraphState(
        repo_path=repo,
        records=[
            {"path_normalized": "src/app.js", "extension": ".js", "binary": False},
            {"path_normalized": "src/a.js", "extension": ".js", "binary": False},
            {"path_normalized": "src/b.js", "extension": ".js", "binary": False},
        ],
        evidence_by_path={},
    )
    ag.parse_js_ts(state, "src/app.js")
    import_edges = [edge for edge in state.edges.values() if edge["type"] == "imports"]
    assert len(import_edges) == 2
    assert all(edge["conditional"] for edge in import_edges)
    assert {edge["weight"] for edge in import_edges} == {0.5}


# --- Cluster 3: builder / portability ---------------------------------------

def test_b06_unknown_node_type_raises() -> None:
    with pytest.raises(acg.CanonicalGraphError):
        acg.add_node({}, "x:1", "not-a-type", "label")


def test_b06_unknown_edge_type_raises() -> None:
    with pytest.raises(acg.CanonicalGraphError):
        acg.add_edge({}, "a", "b", "not-an-edge")


def test_b08_repo_node_id_constant() -> None:
    assert acg.REPO_NODE_ID == "repo:target"


def test_b09_normalize_graph_path_uses_posix_separators() -> None:
    assert acg.normalize_graph_path("src\\foo\\bar.py") == "src/foo/bar.py"


def test_b09_b15_windows_symbol_path_resolves_to_module_without_orphan(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    module_graph = {"nodes": [{"id": "module:src/foo.py", "type": "module", "path": "src/foo.py", "evidence_ids": []}], "edges": []}
    symbol_index = {"symbols": [{"symbol_id": "symbol:src/foo.py:bar:1", "name": "bar", "path": "src\\foo.py", "evidence_ids": []}]}
    graph = acg.build_canonical_graph(audit_dir, {"repo": {}}, module_graph, symbol_index)
    # B15: no edge silently dropped; B09: the symbol->module contains edge resolved.
    assert graph["derivations"]["dropped_edge_count"] == 0
    contains = [e for e in graph["edges"] if e["type"] == "contains" and e["target"] == "symbol:src/foo.py:bar:1"]
    assert contains and contains[0]["source"] == "module:src/foo.py"


# --- Cluster 2: validator ---------------------------------------------------

def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def test_b14_empty_graph_fails_validation(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _write(audit_dir / ARTIFACT_PATHS["GRAPH"], {"schema_version": "1.0", "nodes": [], "edges": [], "derivations": {"source_artifacts": ["FILE_INDEX.json"]}})
    errors = validate_canonical_graph_artifacts(audit_dir, {"evidence": []})
    assert any("no valid nodes" in e for e in errors)


def test_b14_graph_missing_root_node_fails_validation(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    node = {"id": "module:src/foo.py", "type": "module", "label": "src/foo.py", "evidence_ids": []}
    _write(audit_dir / ARTIFACT_PATHS["GRAPH"], {"schema_version": "1.0", "nodes": [node], "edges": [], "derivations": {"source_artifacts": ["FILE_INDEX.json"]}})
    errors = validate_canonical_graph_artifacts(audit_dir, {"evidence": []})
    assert any("repo:target" in e for e in errors)


def test_b15_nonzero_dropped_edge_count_fails_validation(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    graph = {
        "schema_version": "1.0",
        "nodes": [{"id": acg.REPO_NODE_ID, "type": "repo", "label": "target", "evidence_ids": []}],
        "edges": [],
        "derivations": {"source_artifacts": ["FILE_INDEX.json"], "dropped_edge_count": 1},
    }
    _write(audit_dir / ARTIFACT_PATHS["GRAPH"], graph)
    errors = validate_canonical_graph_artifacts(audit_dir, {"evidence": []})
    assert any("dropped_edge_count must be zero" in e for e in errors)


def test_b11_recompose_mismatch_sample_reports_order_only_mismatch() -> None:
    sample = recompose_mismatch_sample([{"id": "a"}, {"id": "b"}], [{"id": "b"}, {"id": "a"}])
    assert "different order" in sample


def test_td7_graph_read_source_bytes_degrades_on_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    state = ag.GraphState(repo_path=Path("."), records=[], evidence_by_path={})

    def raise_oserror(*_args: Any, **_kwargs: Any) -> bytes:
        raise OSError("[WinError 206] path too long")

    monkeypatch.setattr(ag, "read_bytes_capped", raise_oserror)

    assert ag.read_source_bytes(state, "src/too_long.py") is None
    assert state.coverage_notes == ["src/too_long.py: graph parse skipped: [WinError 206] path too long"]


def test_td7_graph_edges_sort_by_full_identity() -> None:
    ordered = sorted(
        [
            {"source": "module:a", "target": "module:b", "type": "imports", "conditional": True, "dynamic": False},
            {"source": "module:a", "target": "module:b", "type": "imports", "conditional": False, "dynamic": False},
            {"source": "module:a", "target": "module:b", "type": "imports", "conditional": False, "dynamic": True},
        ],
        key=ag.graph_edge_sort_key,
    )
    assert [(edge["conditional"], edge["dynamic"]) for edge in ordered] == [(False, False), (False, True), (True, False)]


def test_td7_call_edges_sort_by_full_identity() -> None:
    ordered = sorted(
        [
            {"caller": "symbol:a", "callee": "symbol:b", "conditional": True, "dynamic": False},
            {"caller": "symbol:a", "callee": "symbol:b", "conditional": False, "dynamic": False},
            {"caller": "symbol:a", "callee": "symbol:b", "conditional": False, "dynamic": True},
        ],
        key=ag.call_edge_sort_key,
    )
    assert [(edge["conditional"], edge["dynamic"]) for edge in ordered] == [(False, False), (False, True), (True, False)]


def test_td7_run_graph_outputs_edges_in_full_identity_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    audit_dir = tmp_path / "audit"
    repo = tmp_path / "repo"
    audit_dir.mkdir()
    repo.mkdir()
    _write(
        audit_dir / ARTIFACT_PATHS["FILE_INDEX"],
        {"schema_version": "1.0", "repo": {"path": str(repo)}, "records": [], "skipped_paths": [], "root_documents": []},
    )
    _write(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"], {"schema_version": "1.0", "evidence": []})

    def fake_extract_graph(state: ag.GraphState) -> None:
        state.nodes["module:a"] = {"id": "module:a", "type": "module", "path": "a.py", "evidence_ids": []}
        state.nodes["module:b"] = {"id": "module:b", "type": "module", "path": "b.py", "evidence_ids": []}
        ag.add_edge(state, "module:a", "module:b", "imports", 0.5, True, False, [])
        ag.add_edge(state, "module:a", "module:b", "imports", 0.25, False, True, [])
        ag.add_edge(state, "module:a", "module:b", "imports", 1.0, False, False, [])
        ag.add_call(state, "symbol:a", "symbol:b", "a.py", True, False, [])
        ag.add_call(state, "symbol:a", "symbol:b", "a.py", False, True, [])
        ag.add_call(state, "symbol:a", "symbol:b", "a.py", False, False, [])

    monkeypatch.setattr(ag, "extract_graph", fake_extract_graph)
    monkeypatch.setattr(ag, "run_canonical_graph_outputs", lambda *_args, **_kwargs: None)

    ag.run_graph({"repo": {"path": str(repo)}, "run_id": "run-graph"}, audit_dir)

    module_graph = json.loads((audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"]).read_text(encoding="utf-8"))
    call_graph = json.loads((audit_dir / ARTIFACT_PATHS["CALL_GRAPH"]).read_text(encoding="utf-8"))
    assert [(edge["conditional"], edge["dynamic"]) for edge in module_graph["edges"]] == [(False, False), (False, True), (True, False)]
    assert [(edge["conditional"], edge["dynamic"]) for edge in call_graph["edges"]] == [(False, False), (False, True), (True, False)]


def test_tesla01_validator_accepts_windows_symbol_path_edge(tmp_path: Path) -> None:
    # TESLA-01 regression: builder normalizes the symbol path (B09); the validator's expected-key
    # set must do the same or it falsely reports the symbol->module edge as missing.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    module_graph = {
        "schema_version": "1.0",
        "nodes": [{"id": "module:src/foo.py", "type": "module", "path": "src/foo.py", "evidence_ids": []}],
        "edges": [],
        "coverage": {},
    }
    symbol_index = {
        "schema_version": "1.0",
        "symbols": [
            {
                "symbol_id": "symbol:src/foo.py:bar:1",
                "name": "bar",
                "kind": "function",
                "path": "src\\foo.py",
                "span": {"start_line": 1, "end_line": 1, "start_byte": 0, "end_byte": 0},
                "public": True,
                "evidence_ids": [],
            }
        ],
    }
    graph = acg.build_canonical_graph(audit_dir, {"repo": {}}, module_graph, symbol_index)
    acg.write_derived_exports(audit_dir, graph)
    acg.write_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"], module_graph)
    acg.write_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"], symbol_index)
    errors = validate_canonical_graph_artifacts(audit_dir, {"evidence": []})
    assert not any("missing expected graph edges" in error for error in errors), errors
