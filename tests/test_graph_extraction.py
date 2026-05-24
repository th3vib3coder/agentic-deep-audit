from __future__ import annotations

import json
import shutil
from pathlib import Path

from agentic_deep_audit.audit_graph import run_graph
from agentic_deep_audit.audit_inventory import run_inventory
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.bootstrap import bootstrap_audit
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, tmp_path: Path) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def config_for(repo: Path, output: Path, algorithm: str = "weighted_in_degree") -> dict:
    return {
        "run_id": "run-graph",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(output),
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
        "graph": {"centrality": {"algorithm": algorithm, "normal_import_weight": 1.0, "conditional_import_weight": 0.5, "tie_break": ["size_bytes_desc", "path_normalized_asc"]}},
    }


def build_graph(repo: Path, output: Path, algorithm: str = "weighted_in_degree") -> Path:
    run_config = config_for(repo, output, algorithm)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")
    run_config["provenance"] = {"config_path": str(config_path)}
    audit_dir = bootstrap_audit(run_config, cwd=repo)
    run_inventory(run_config, audit_dir)
    run_graph(run_config, audit_dir)
    return audit_dir


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_python_fixture_extracts_modules_symbols_calls_and_weights(tmp_path: Path) -> None:
    repo = copy_fixture("python_basic", tmp_path)
    audit_dir = build_graph(repo, repo / "audit")

    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    symbol_index = load_json(audit_dir / ARTIFACT_PATHS["SYMBOL_INDEX"])
    evidence_ids = {item["id"] for item in load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])["evidence"]}

    assert "module:src/app.py" in {node["id"] for node in module_graph["nodes"]}
    assert "module:src/utils.py" in {node["id"] for node in module_graph["nodes"]}
    normal = next(edge for edge in module_graph["edges"] if edge["source"] == "module:src/app.py" and edge["target"] == "module:src/utils.py")
    assert normal["weight"] == 1.0
    conditional = next(edge for edge in module_graph["edges"] if edge["target"] == "package:json")
    assert conditional["conditional"] is True
    assert conditional["weight"] == 0.5
    assert module_graph["centrality"]["module:src/utils.py"]["algorithm"] == "weighted_in_degree"
    assert module_graph["centrality"]["module:src/utils.py"]["score"] >= 1.0

    symbols = {symbol["name"]: symbol for symbol in symbol_index["symbols"]}
    for required in ["main", "Greeter", "Greeter.greet", "__main__"]:
        assert required in symbols
        assert set(symbols[required]["evidence_ids"]).issubset(evidence_ids)
        assert symbols[required]["span"]["end_byte"] >= symbols[required]["span"]["start_byte"]

    call_graph = load_json(audit_dir / ARTIFACT_PATHS["CALL_GRAPH"])
    assert any(edge["type"] == "calls" and edge["caller"].startswith("symbol:src/app.py:function:main") for edge in call_graph["edges"])
    assert validate_audit(audit_dir).ok


def test_js_ts_fixture_marks_dynamic_require_partial_without_guessing(tmp_path: Path) -> None:
    repo = copy_fixture("js_ts_basic", tmp_path)
    audit_dir = build_graph(repo, repo / "audit-js")

    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    assert any(edge["source"] == "module:src/index.ts" and edge["target"] == "module:src/util.ts" for edge in module_graph["edges"])
    assert "dynamic require skipped" in module_graph["partial_reason"]
    assert not any("RUNTIME_PLUGIN" in edge["target"] for edge in module_graph["edges"])
    assert (audit_dir / ARTIFACT_PATHS["CALL_GRAPH_SKIPPED"]).exists()
    assert not (audit_dir / ARTIFACT_PATHS["CALL_GRAPH"]).exists()
    assert validate_audit(audit_dir).ok


def test_minimal_language_parsers_emit_partial_notes(tmp_path: Path) -> None:
    repo = tmp_path / "multi"
    repo.mkdir()
    (repo / "main.go").write_text('package main\nimport "fmt"\nfunc main() { fmt.Println("ok") }\n', encoding="utf-8")
    (repo / "lib.rs").write_text("use crate::inner;\nfn run() {}\n", encoding="utf-8")
    (repo / "App.java").write_text("import java.util.List;\nclass App {}\n", encoding="utf-8")
    (repo / "extension.rb").write_text("puts 'generic'\n", encoding="utf-8")
    audit_dir = build_graph(repo, repo / "audit-multi")

    module_graph = load_json(audit_dir / ARTIFACT_PATHS["MODULE_GRAPH"])
    notes = "\n".join(module_graph["coverage"]["notes"])
    assert "go parser minimal" in notes
    assert "rust parser minimal" in notes
    assert "java/kotlin parser minimal" in notes
    assert "no language parser available" in notes
    assert any(edge["target"] == "package:fmt" for edge in module_graph["edges"])


def test_graph_validation_rejects_missing_default_tie_break(tmp_path: Path) -> None:
    repo = copy_fixture("python_basic", tmp_path)
    audit_dir = build_graph(repo, repo / "audit-tie")
    run_config_path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    run_config = load_json(run_config_path)
    run_config["graph"]["centrality"].pop("tie_break")
    run_config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("tie_break" in error for error in result.errors)


def test_architecture_baseline_update_preserves_later_sections(tmp_path: Path) -> None:
    repo = copy_fixture("python_basic", tmp_path)
    audit_dir = build_graph(repo, repo / "audit-arch")
    architecture = audit_dir / ARTIFACT_PATHS["ARCHITECTURE"]
    architecture.write_text(architecture.read_text(encoding="utf-8") + "\n## Synthesis\n\nHuman-authored synthesis.\n", encoding="utf-8")

    run_graph(config_for(repo, repo / "audit-arch"), audit_dir)

    text = architecture.read_text(encoding="utf-8")
    assert text.count("## Baseline") == 1
    assert "## Synthesis" in text
    assert "Human-authored synthesis." in text
