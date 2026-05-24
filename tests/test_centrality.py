from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_graph import compute_centrality
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, tmp_path: Path) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def config_for(repo: Path, output: Path) -> dict:
    return {
        "run_id": "run-graph",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(output),
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
        "graph": {
            "centrality": {
                "algorithm": "weighted_in_degree",
                "normal_import_weight": 1.0,
                "conditional_import_weight": 0.5,
                "tie_break": ["size_bytes_desc", "path_normalized_asc"],
            }
        },
    }


def test_default_algorithm() -> None:
    nodes = [{"id": "module:a.py", "type": "module"}, {"id": "module:b.py", "type": "module"}]
    edges = [{"source": "module:a.py", "target": "module:b.py", "weight": 1.0}]

    default = compute_centrality(nodes, edges)
    total = compute_centrality(nodes, edges, "degree_total")
    pagerank = compute_centrality(nodes, edges, "pagerank_if_available")

    assert default["module:b.py"]["algorithm"] == "weighted_in_degree"
    assert default["module:b.py"]["score"] == 1.0
    assert total["module:a.py"]["score"] == 1.0
    assert pagerank["module:b.py"]["score"] > pagerank["module:a.py"]["score"]


def test_override_logging(tmp_path: Path) -> None:
    repo = copy_fixture("python_basic", tmp_path)
    config_path = repo / "audit.config.json"
    output = repo / "graph-cli"
    config_path.write_text(json.dumps(config_for(repo, output), indent=2), encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentic_deep_audit.cli",
            "graph",
            "--config",
            str(config_path),
            "--graph-centrality",
            "pagerank_if_available",
        ],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    run_config = load_json(output / ARTIFACT_PATHS["RUN_CONFIG"])
    assert run_config["graph"]["centrality"]["algorithm"] == "pagerank_if_available"
    assert run_config["override_source"]["graph.centrality.algorithm"] == "argv"
    tools = load_json(output / ARTIFACT_PATHS["TOOL_STATUS"])["tools"]
    centrality = next(tool for tool in tools if tool["tool"] == "centrality_scorer")
    assert "override algorithm=pagerank_if_available" in centrality["notes"][0]
