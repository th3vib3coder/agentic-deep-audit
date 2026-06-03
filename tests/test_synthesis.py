from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_graph import run_graph
from agentic_deep_audit.audit_inventory import run_inventory
from agentic_deep_audit.audit_manifest import run_manifest
from agentic_deep_audit.audit_surface import run_surface
from agentic_deep_audit.audit_synthesis import decision_doc_questions, enrich_architecture, markdown_cell, run_synthesis
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.bootstrap import bootstrap_audit
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, tmp_path: Path) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def config_for(repo: Path, output: Path) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": "run-synthesis",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(output),
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
        "graph": {"centrality": {"algorithm": "weighted_in_degree", "normal_import_weight": 1.0, "conditional_import_weight": 0.5, "tie_break": ["size_bytes_desc", "path_normalized_asc"]}},
    }


def build_surface(repo: Path, output: Path) -> tuple[Path, dict]:
    run_config = config_for(repo, output)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")
    run_config["provenance"] = {"config_path": str(config_path)}
    audit_dir = bootstrap_audit(run_config, cwd=repo)
    run_inventory(run_config, audit_dir)
    run_manifest(run_config, audit_dir)
    run_graph(run_config, audit_dir)
    run_surface(run_config, audit_dir)
    return audit_dir, run_config


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_architecture_agent_handoff_is_read_only() -> None:
    handoff = load_json(PLUGIN_ROOT / "docs" / "agents" / "architecture-agent-handoff.json")

    assert handoff["mode"] == "read-only-synthesis"
    assert handoff["target_repo_write_access"] is False
    assert set(handoff["read_only_inputs"]) >= {"MODULE_GRAPH.json", "SYMBOL_INDEX.json", "EVIDENCE_INDEX.json"}


def test_synthesis_preserves_baseline_and_generates_evidence_backed_outputs(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-synthesis")
    architecture = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    raw_baseline = "## Baseline\n\n- keep me  \n\n### Detail\n\n- nested  \n"
    architecture.write_text("# Architecture\n\n" + raw_baseline + "\n## Prior Synthesis\n\n- stale\n", encoding="utf-8")

    run_synthesis(run_config, audit_dir)

    architecture_after = architecture.read_text(encoding="utf-8")
    baseline_after = architecture_after[architecture_after.index("## Baseline") : architecture_after.index("\n## Evidence-Backed Synthesis")]
    assert baseline_after == raw_baseline
    feature_text = (audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]).read_text(encoding="utf-8")
    pattern_text = (audit_dir / ARTIFACT_PATHS["PATTERNS"]).read_text(encoding="utf-8")
    assert "/health" in feature_text
    assert "Root document README" in feature_text
    assert "ev-" in feature_text
    assert "Public API endpoint" in pattern_text
    assert "ev-" in pattern_text
    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"])
    assert special["candidates"]
    first = special["candidates"][0]
    for key in ["coupling", "dependencies", "license_status_source", "performance_note", "limitations", "evidence_ids"]:
        assert first[key] or key == "dependencies"
    assert validate_audit(audit_dir).ok


def test_special_implementations_excludes_tests_and_ranks_by_centrality(tmp_path: Path) -> None:
    # Decision-grade reuse regression (observed on Lum1104/Understand-Anything): the candidate cap was
    # filled by the FIRST symbols in index order — which are often a test file's symbols — crowding out
    # every production component (Adopt/Adapt/Study ended up empty, Avoid = 20 test classes). The
    # generator must EXCLUDE test-file symbols and rank the rest by module centrality, so reuse
    # candidates are the most-depended-on PRODUCTION components.
    from agentic_deep_audit.audit_synthesis import build_special_implementations

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).write_text(json.dumps({"run_id": "run-rank"}), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).write_text(json.dumps({"evidence": [{"id": "ev-000001", "path": "src/high.py"}]}), encoding="utf-8")
    # FILE_INDEX marks the test file kind=test (authoritative) and production files kind=code.
    (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).write_text(
        json.dumps({"records": [
            {"path": "tests/test_thing.py", "kind": "test"},
            {"path": "src/high.py", "kind": "code"},
            {"path": "src/low.py", "kind": "code"},
            {"path": "src/hub.ts", "kind": "code"},
        ]}),
        encoding="utf-8",
    )
    # 21 test symbols FIRST (would exhaust a 20 cap in index order), then 3 production symbols — one of
    # which is a TS-style `export` (the dominant symbol kind in TS/JS/Go repos) and the most central.
    test_syms = [
        {"name": f"TestCase{i:02d}", "path": "tests/test_thing.py", "kind": "class", "public": True, "evidence_ids": ["ev-000001"], "span": {"start_line": i + 1}}
        for i in range(21)
    ]
    prod_syms = [
        {"name": "HighValue", "path": "src/high.py", "kind": "class", "public": True, "evidence_ids": ["ev-000001"], "span": {"start_line": 1}},
        {"name": "LowValue", "path": "src/low.py", "kind": "function", "public": True, "evidence_ids": ["ev-000001"], "span": {"start_line": 1}},
        {"name": "ExportedHub", "path": "src/hub.ts", "kind": "export", "public": True, "evidence_ids": ["ev-000001"], "span": {"start_line": 1}},
    ]
    symbol_index = {"symbols": test_syms + prod_syms}
    module_graph = {"edges": [], "centrality": {
        "module:src/hub.ts": {"algorithm": "weighted_in_degree", "rank": 1, "score": 20.0},
        "module:src/high.py": {"algorithm": "weighted_in_degree", "rank": 2, "score": 9.0},
        "module:src/low.py": {"algorithm": "weighted_in_degree", "rank": 3, "score": 1.0},
        "module:tests/test_thing.py": {"algorithm": "weighted_in_degree", "rank": 4, "score": 0.0},
    }}

    build_special_implementations(audit_dir, symbol_index, module_graph, {"ev-000001"})

    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"])
    files = {f for candidate in special["candidates"] for f in candidate["files"]}
    names = [candidate["name"] for candidate in special["candidates"]]
    assert "tests/test_thing.py" not in files, "test-file symbols must be excluded from reuse candidates"
    assert {"src/high.py", "src/low.py", "src/hub.ts"} <= files, "production components (incl. exported TS/JS symbols) must reach the candidate set"
    assert names[0] == "ExportedHub", "candidates must be ranked by module centrality across languages (most depended-on export/function first)"
    assert special["total_eligible"] == 3 and special["truncated"] is False, "non-test eligible count is surfaced and not truncated below the cap"


def test_is_test_path_excludes_tests_not_production_spec_or_testing_dirs() -> None:
    # Over-exclusion guard (swarm P2): the heuristic must catch genuine tests in any language WITHOUT
    # dropping production code that merely lives under a `spec/` (OpenAPI) or `testing/` (library) dir.
    from agentic_deep_audit.audit_synthesis import is_test_path

    for genuine_test in ["tests/foo.py", "pkg/__tests__/x.ts", "src/foo.test.ts", "src/foo.spec.ts", "pkg/foo_test.go", "test_foo.py", "spec/models/user_spec.rb"]:
        assert is_test_path(genuine_test), genuine_test
    for production in ["spec/openapi.yaml", "specs/api/users.json", "src/testing/factory.ts", "src/attestation.ts", "pkg/contest.go", "src/latest.py", "api/spec/schema.ts"]:
        assert not is_test_path(production), production


def test_special_implementations_records_truncation(tmp_path: Path) -> None:
    # Transparency (swarm P0): when more components are eligible than the cap, the artifact must record
    # total_eligible + truncated, and a reviewer-facing open question must be returned (not silently cut).
    from agentic_deep_audit.audit_synthesis import build_special_implementations

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).write_text(json.dumps({"run_id": "run-trunc"}), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).write_text(json.dumps({"evidence": [{"id": "ev-000001", "path": "src/m.py"}]}), encoding="utf-8")
    (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).write_text(json.dumps({"records": [{"path": "src/m.py", "kind": "code"}]}), encoding="utf-8")
    syms = [{"name": f"C{i:02d}", "path": "src/m.py", "kind": "function", "public": True, "evidence_ids": ["ev-000001"], "span": {"start_line": i + 1}} for i in range(25)]

    questions = build_special_implementations(audit_dir, {"symbols": syms}, {"edges": [], "centrality": {}}, {"ev-000001"})

    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"])
    assert special["total_eligible"] == 25
    assert special["truncated"] is True
    assert len(special["candidates"]) == 20
    assert any("truncated" in q.lower() for q in questions), "a truncation open-question must be surfaced"


def test_synthesis_flags_evidence_linkage_gap_instead_of_silent_skip(tmp_path: Path) -> None:
    # C6-04: structural artifacts present but with no reachable evidence id must be surfaced as an
    # evidence-linkage gap, not a bare "skipped" that contradicts the visible module count.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    path = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Architecture\n\n## Baseline\n\n- baseline.\n", encoding="utf-8")
    module_graph = {"nodes": [{"id": "module:a", "type": "module"}, {"id": "module:b", "type": "module"}], "edges": []}

    enrich_architecture(audit_dir, module_graph, {"symbols": []}, {})

    text = path.read_text(encoding="utf-8")
    assert "evidence-linkage gap" in text
    assert "2 modules" in text


def test_synthesis_preserves_original_when_no_baseline_section(tmp_path: Path) -> None:
    # C6-05: a document with no "## Baseline" section must not have its original content discarded.
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    path = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Architecture\n\n## Custom Section\n\n- important hand content\n", encoding="utf-8")
    module_graph = {"nodes": [{"id": "module:a", "type": "module"}], "edges": []}

    enrich_architecture(audit_dir, module_graph, {"symbols": []}, {})

    text = path.read_text(encoding="utf-8")
    assert "important hand content" in text


def test_feature_without_evidence_moves_to_open_questions(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-open")
    api_path = audit_dir / ARTIFACT_PATHS["API_SURFACE"]
    api = load_json(api_path)
    api["records"][0]["evidence_ids"] = []
    api_path.write_text(json.dumps(api, indent=2) + "\n", encoding="utf-8")

    run_synthesis(run_config, audit_dir)

    open_questions = (audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"]).read_text(encoding="utf-8")
    assert "lacks reachable evidence" in open_questions


def test_synthesis_escapes_markdown_table_cells_before_graph_promotion(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-table-escape")
    api_path = audit_dir / ARTIFACT_PATHS["API_SURFACE"]
    api = load_json(api_path)
    api["records"][0]["path"] = "evil | injected"
    api["records"][0]["source_path"] = "src/app.py | phantom"
    api_path.write_text(json.dumps(api, indent=2) + "\n", encoding="utf-8")

    run_synthesis(run_config, audit_dir)

    feature_text = (audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]).read_text(encoding="utf-8")
    assert "evil \\| injected" in feature_text
    assert "src/app.py \\| phantom" in feature_text
    assert "src/app.py | phantom" not in feature_text


def test_markdown_cell_strips_zero_width_and_bidi_categories() -> None:
    cell = markdown_cell("ev-\u061c999999\u202e | visible\u200b")

    assert cell == "ev\\-999999 \\| visible"
    assert "\u061c" not in cell
    assert "\u202e" not in cell
    assert "\u200b" not in cell


def test_synthesis_validation_rejects_broken_markdown_and_json_evidence(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-broken")
    run_synthesis(run_config, audit_dir)
    feature_path = audit_dir / ARTIFACT_PATHS["FEATURE_CATALOG"]
    feature_text = feature_path.read_text(encoding="utf-8")
    first_evidence = re.search(r"ev-\d{6}", feature_text).group(0)
    feature_path.write_text(feature_text.replace(first_evidence, "ev-999999", 1), encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("FEATURE_CATALOG.md references unreachable evidence id" in error for error in result.errors)


def test_synthesis_validation_rejects_broken_special_implementation_evidence(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-broken-json")
    run_synthesis(run_config, audit_dir)
    special_path = audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"]
    special = load_json(special_path)
    special["candidates"][0]["evidence_ids"] = ["ev-999999"]
    special_path.write_text(json.dumps(special, indent=2) + "\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("SPECIAL_IMPLEMENTATIONS.json.candidates[0].evidence_ids references unreachable evidence id" in error for error in result.errors)


def test_synthesis_validation_rejects_architecture_claim_without_evidence(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-architecture-evidence")
    run_synthesis(run_config, audit_dir)
    architecture_path = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    architecture_text = architecture_path.read_text(encoding="utf-8")
    architecture_path.write_text(re.sub(r"Evidence: `ev-\d{6}`(?:, `ev-\d{6}`)?", "Evidence: ", architecture_text, count=1), encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("ARCHITECTURE.md synthesis claim lacks evidence id" in error for error in result.errors)


def test_synthesis_validation_rejects_invalid_license_status_source(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir, run_config = build_surface(repo, repo / "audit-license-source")
    run_synthesis(run_config, audit_dir)
    special_path = audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"]
    special = load_json(special_path)
    special["candidates"][0]["license_status_source"] = "unreviewed"
    special_path.write_text(json.dumps(special, indent=2) + "\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("invalid license_status_source" in error for error in result.errors)


def test_decision_doc_scan_requires_changelog_decision_marker(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    changelog = repo / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n- Added endpoint.\n", encoding="utf-8")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "repo": {"path": str(repo)},
                "records": [{"path": "CHANGELOG.md", "path_normalized": "CHANGELOG.md"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    skipped = decision_doc_questions(audit_dir)
    changelog.write_text("# Changelog\n\n- Decision: retain synchronous API.\n", encoding="utf-8")

    assert skipped
    assert decision_doc_questions(audit_dir) == []


def test_decision_doc_scan_rejects_changelog_traversal(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "CHANGELOG.md").write_text("# Changelog\n\n- Architecture decision: escape.\n", encoding="utf-8")
    (outside / "ADR.md").write_text("# ADR\n\n- accepted.\n", encoding="utf-8")
    (outside / "decision.md").write_text("# Decision\n\n- accepted.\n", encoding="utf-8")
    (outside / "architecture.md").write_text("# Architecture\n\n- accepted.\n", encoding="utf-8")
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    traversal_records = [
        "../outside/CHANGELOG.md",
        "../outside/ADR.md",
        "../outside/decision.md",
        "../outside/architecture.md",
        str(outside / "ADR.md"),
        "..\\outside\\ADR.md",
    ]
    (audit_dir / ARTIFACT_PATHS["FILE_INDEX"]).write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "repo": {"path": str(repo)},
                "records": [{"path": path, "path_normalized": path} for path in traversal_records],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert decision_doc_questions(audit_dir)


def test_cli_synthesis_command_wires_outputs(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(config_for(repo, repo / "audit-cli-synthesis"), indent=2) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", "synthesis", "--config", str(config_path)],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit-cli-synthesis"
    for artifact in ["FEATURE_CATALOG", "PATTERNS", "SPECIAL_IMPLEMENTATIONS", "OPEN_QUESTIONS"]:
        assert (audit_dir / ARTIFACT_PATHS[artifact]).exists()
