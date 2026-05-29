from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from fixture_matrix import AUTHORITATIVE_FIXTURES
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT
from run_smoke_tests import DEFAULT_FIXTURES


FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"
SRC_ROOT = PLUGIN_ROOT / "src"
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
    authoritative = set(AUTHORITATIVE_FIXTURES)

    assert authoritative <= observed
    assert set(FIXTURE_TEST_COVERAGE) == authoritative
    for fixture, tests in FIXTURE_TEST_COVERAGE.items():
        assert tests, fixture
        for test_name in tests:
            assert (PLUGIN_ROOT / "tests" / test_name).exists(), f"{fixture} missing {test_name}"


def test_default_smoke_fixtures_cover_every_authoritative_fixture() -> None:
    assert set(DEFAULT_FIXTURES) == set(AUTHORITATIVE_FIXTURES)
    for fixture in DEFAULT_FIXTURES:
        assert (FIXTURE_ROOT / fixture / "audit.config.yaml").exists(), f"{fixture} missing audit.config.yaml"


def test_ci_workflow_runs_required_gates() -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "agentic-deep-audit.yml"
    text = workflow.read_text(encoding="utf-8")

    for expected in [
        "pytest tests -q",
        "tests/run_smoke_tests.py",
        "compileall",
        "Git-dependent coverage must not skip",
        "git --version",
        "audit/git-dependent-pytest.log",
        "! grep -q '^SKIPPED'",
        "tests/test_provenance_git_github.py::test_git_provenance_uses_allowlisted_commands_and_redacts_remote",
        "tests/test_project_telemetry.py::test_git_telemetry_changelog_identity_and_manifest_caveats",
        "tests/test_evidence_byte_ranges.py::test_git_provenance_commit_is_synced_to_evidence_index",
    ]:
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
