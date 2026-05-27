from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_quality import quality_markdown, test_coverage_signal as build_coverage_signal
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


def copy_fixture(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_run_command_wires_performance_quality_outputs(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")

    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    for key in ["PERFORMANCE_REVIEW", "QUALITY_REVIEW", "TEST_COVERAGE_SIGNAL", "AUDIT_RUNTIME_METRICS"]:
        assert (audit_dir / ARTIFACT_PATHS[key]).exists()
    assert validate_audit(audit_dir).ok


def test_performance_review_separates_proxy_benchmark_and_claim_only(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr

    text = (repo / "audit" / ARTIFACT_PATHS["PERFORMANCE_REVIEW"]).read_text(encoding="utf-8")

    assert "Static proxy signals are not runtime benchmarks" in text
    assert "benchmarks/bench_api.py" in text
    assert "claim-only" in text
    assert "Large files: 1" in text
    assert "Large functions: 2" in text
    assert "proxy benchmark" not in text.lower()
    assert "Cyclomatic complexity: skipped" in text


def test_test_coverage_signal_never_invents_percentage_without_artifact(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr

    text = (repo / "audit" / ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"]).read_text(encoding="utf-8")

    assert "Coverage artifact files observed: 0" in text
    assert "Skipped: no coverage artifact" in text
    assert "%" not in text


def test_quality_score_does_not_award_free_point_without_risk_review() -> None:
    text = quality_markdown(
        {"records": [{"path": "README.md", "kind": "docs"}]},
        {},
        {"records": []},
        {},
        {"test_files": [], "ci_commands": 0, "numeric_coverage": [], "coverage_files": []},
    )

    assert "Evidence-weighted quality signal: 1/5." in text


def test_quality_score_does_not_award_free_point_for_empty_risk_findings() -> None:
    text = quality_markdown(
        {"records": [{"path": "README.md", "kind": "docs"}]},
        {},
        {"records": []},
        {"schema_version": "1.0", "findings": []},
        {"test_files": [], "ci_commands": 0, "numeric_coverage": [], "coverage_files": []},
    )

    assert "Evidence-weighted quality signal: 1/5." in text


def test_coverage_signal_ignores_out_of_range_coverage_percent(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "coverage.xml").write_text('<coverage line-rate="9999"></coverage>', encoding="utf-8")
    file_index = {"records": [{"path": "coverage.xml", "path_normalized": "coverage.xml", "kind": "docs"}]}

    coverage = build_coverage_signal(file_index, "| command | `pytest` |\n", {"records": []}, repo, {})

    assert coverage["numeric_coverage"] == []
    assert coverage["ci_test_command_count"] == 1


def test_runtime_metrics_are_plugin_scoped_and_memory_skip_not_zero(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr

    metrics = load_json(repo / "audit" / ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"])

    assert "audit plugin, not the audited project" in " ".join(metrics["notes"])
    assert metrics["files_processed"] > 0
    assert metrics["bytes_processed"] > 0
    assert metrics["phase_durations_ms"]["performance_quality"]["duration_ms"] >= 0
    for phase, record in metrics["phase_durations_ms"].items():
        assert "duration_ms" in record or "skipped_reason" in record, phase
    assert metrics["memory_peak"]["status"] == "skipped"
    assert metrics["memory_peak"].get("value") != 0


def test_validator_rejects_missing_caveats(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    performance = audit_dir / ARTIFACT_PATHS["PERFORMANCE_REVIEW"]
    performance.write_text(performance.read_text(encoding="utf-8").replace("Static proxy signals are not runtime benchmarks.", ""), encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("observed/proxy distinction" in error for error in validation.errors)


def test_validator_rejects_runtime_metrics_missing_required_seq020_fields(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    metrics = load_json(audit_dir / ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"])
    for key in ["files_processed", "bytes_processed", "output_bytes", "cache_hits", "cache_misses", "tool_failures", "token_proxy", "memory_peak"]:
        metrics.pop(key, None)
    metrics_path = audit_dir / ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"]
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("files_processed" in error for error in validation.errors)
    assert any("token_proxy" in error for error in validation.errors)
    assert any("memory_peak" in error for error in validation.errors)


def test_validator_rejects_coverage_percent_without_count_and_artifact(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    signal = audit_dir / ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"]
    text = signal.read_text(encoding="utf-8")
    signal.write_text(text.replace("- Coverage artifact files observed: 0.\n", "") + "\n- Claimed coverage: 85%.\n", encoding="utf-8")

    missing_count = validate_audit(audit_dir)

    assert not missing_count.ok
    assert any("missing coverage artifact count" in error for error in missing_count.errors)

    signal.write_text(text + "\n- Claimed coverage: 85%.\n", encoding="utf-8")
    no_artifact = validate_audit(audit_dir)

    assert not no_artifact.ok
    assert any("without coverage artifact" in error for error in no_artifact.errors)


def test_run_dry_run_lists_phase_7_artifacts(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")

    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), "--dry-run", cwd=repo)

    assert result.returncode == 0, result.stderr
    planned = set(json.loads(result.stdout)["planned_artifacts"])
    assert {ARTIFACT_PATHS["PERFORMANCE_REVIEW"], ARTIFACT_PATHS["QUALITY_REVIEW"], ARTIFACT_PATHS["TEST_COVERAGE_SIGNAL"], ARTIFACT_PATHS["AUDIT_RUNTIME_METRICS"]} <= planned
