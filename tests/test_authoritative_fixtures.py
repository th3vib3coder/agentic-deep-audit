from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"
SRC_ROOT = PLUGIN_ROOT / "src"
AUTHORITATIVE_FIXTURES = {
    "python_basic",
    "js_ts_basic",
    "mixed_risky",
    "license_manifest",
    "license_file_level_mixed",
    "agentic_injection",
    "binary_artifacts",
    "scientific_data_project",
    "no_git_repo",
    "blocked_command_attempt",
    "markdown_prompt_injection",
    "mcp_collision_detected",
    "network_precedence_check",
    "mcp_host_secret_redact",
}
FIXTURE_TEST_COVERAGE = {
    "python_basic": ["test_inventory_file_index.py", "test_graph_extraction.py", "test_canonical_graph.py"],
    "js_ts_basic": ["test_graph_extraction.py"],
    "mixed_risky": ["test_risk_security.py", "test_canonical_graph.py"],
    "license_manifest": ["test_license_binary.py"],
    "license_file_level_mixed": ["test_license_binary.py"],
    "agentic_injection": ["test_risk_security.py"],
    "binary_artifacts": ["test_license_binary.py"],
    "scientific_data_project": ["test_scientific_provenance.py"],
    "no_git_repo": ["test_project_telemetry.py", "test_provenance_git_github.py"],
    "blocked_command_attempt": ["test_pre_tool_policy.py"],
    "markdown_prompt_injection": ["test_pre_tool_policy.py"],
    "mcp_collision_detected": ["test_fixture_mcp_policy.py"],
    "network_precedence_check": ["test_network_policy.py"],
    "mcp_host_secret_redact": ["test_fixture_mcp_policy.py"],
}


def test_all_authoritative_fixtures_exist_and_have_coverage() -> None:
    observed = {path.name for path in FIXTURE_ROOT.iterdir() if path.is_dir()}

    assert AUTHORITATIVE_FIXTURES <= observed
    assert set(FIXTURE_TEST_COVERAGE) == AUTHORITATIVE_FIXTURES
    for fixture, tests in FIXTURE_TEST_COVERAGE.items():
        assert tests, fixture
        for test_name in tests:
            assert (PLUGIN_ROOT / "tests" / test_name).exists(), f"{fixture} missing {test_name}"


def test_ci_workflow_runs_required_gates() -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "agentic-deep-audit.yml"
    text = workflow.read_text(encoding="utf-8")

    for expected in ["pytest tests -q", "tests/run_smoke_tests.py", "compileall"]:
        assert expected in text


def test_python_basic_fixture_runs_cli_inventory_graph_and_wiki(tmp_path: Path) -> None:
    repo = tmp_path / "python_basic"
    shutil.copytree(FIXTURE_ROOT / "python_basic", repo)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", "wiki", "--config", str(repo / "audit.config.yaml")],
        cwd=repo,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    audit_dir = repo / "audit"

    assert result.returncode == 0, result.stderr
    for key in ["CLI_SURFACE", "INVENTORY", "MODULE_GRAPH", "WIKI_HOME"]:
        assert (audit_dir / ARTIFACT_PATHS[key]).exists()
