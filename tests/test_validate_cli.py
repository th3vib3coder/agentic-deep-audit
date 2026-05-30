from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import agentic_deep_audit.audit_validate as audit_validate_module
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "agentic_deep_audit.cli", *args], cwd=cwd, env=cli_env(), check=False, text=True, capture_output=True)


def copy_fixture(tmp_path: Path, name: str = "performance_quality_project") -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_full_audit(tmp_path: Path) -> Path:
    repo = copy_fixture(tmp_path)
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def test_missing_audit_dir() -> None:
    result = run_cli("validate", "--audit-dir", "missing-audit", cwd=PLUGIN_ROOT)

    assert result.returncode != 0
    assert "missing audit dir" in result.stderr


def test_validate_audit_isolates_phase_validator_exceptions(tmp_path: Path, monkeypatch) -> None:
    # OQ-M11: a phase validator raising on a malformed artifact must be reported as a blocker,
    # not abort the whole validation run. Previously only the extension/review-packet validators
    # were exception-guarded; the 11 phase validators ran bare, so one KeyError aborted everything.
    audit_dir = build_full_audit(tmp_path)

    def boom(*args: object, **kwargs: object):
        raise KeyError("simulated malformed artifact")

    monkeypatch.setattr(audit_validate_module, "validate_graph_artifacts", boom)
    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("validation_exception" in error and "KeyError" in error for error in result.errors)


def test_validate_cli_writes_zero_blocker_report(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=audit_dir.parent)
    report = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")

    assert result.returncode == 0, result.stderr
    assert "Blocker count: `0`" in report
    assert "## Commands Run" in report


def test_validate_cli_writes_report_for_malformed_json(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    (audit_dir / ARTIFACT_PATHS["GRAPH"]).write_text("{not-json", encoding="utf-8")

    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=audit_dir.parent)
    report = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")

    assert result.returncode != 0
    assert "json_parse:" in report or "invalid graph JSON artifact" in report
    assert "## Blockers" in report


def test_graph_schema_blocker_is_reported(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph.pop("nodes")
    write_json(graph_path, graph)

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("graph_schema:" in error for error in result.errors)


def test_anti_overclaim_language_blocks_unscoped_final_claim(tmp_path: Path) -> None:
    audit_dir = build_full_audit(tmp_path)
    (audit_dir / ARTIFACT_PATHS["REPORT"]).write_text("# Report\n\nThis audit is 100% complete and guaranteed secure.\n", encoding="utf-8")

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("anti_overclaim" in error for error in result.errors)

    # TQ-007: negative case — a properly scoped claim must NOT trip the anti-overclaim guard, so
    # the rule is not simply flagging every "100%".
    (audit_dir / ARTIFACT_PATHS["REPORT"]).write_text("# Report\n\nWithin the analyzed scope, coverage is 100% complete.\n", encoding="utf-8")
    scoped_result = validate_audit(audit_dir)
    assert not any("anti_overclaim" in error for error in scoped_result.errors)
