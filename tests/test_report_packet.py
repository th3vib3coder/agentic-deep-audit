from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_report import ReportGateError, artifact_inventory, generate_report_artifacts, validation_passed
from agentic_deep_audit.audit_validate import validate_audit
from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT
from agentic_deep_audit.validate_report_packet import validate_review_packet

SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "agentic_deep_audit.cli", *args], cwd=cwd, env=cli_env(), check=False, text=True, capture_output=True)


def copy_fixture(tmp_path: Path) -> Path:
    repo = tmp_path / "performance_quality_project"
    shutil.copytree(FIXTURES / "performance_quality_project", repo)
    return repo


def build_validated_audit(tmp_path: Path) -> Path:
    repo = copy_fixture(tmp_path)
    run = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert run.returncode == 0, run.stderr
    audit_dir = repo / "audit"
    validate = run_cli("validate", "--audit-dir", str(audit_dir), cwd=repo)
    assert validate.returncode == 0, validate.stderr
    return audit_dir


def test_validate_generates_final_report_open_questions_ledger_and_packet(tmp_path: Path) -> None:
    audit_dir = build_validated_audit(tmp_path)

    for key in ["REPORT", "OPEN_QUESTIONS", "REVIEW_LEDGER", "ADVERSARIAL_REVIEW_PACKET"]:
        assert (audit_dir / ARTIFACT_PATHS[key]).exists()
    report = (audit_dir / ARTIFACT_PATHS["REPORT"]).read_text(encoding="utf-8")
    packet = (audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]).read_text(encoding="utf-8")
    open_questions = (audit_dir / ARTIFACT_PATHS["OPEN_QUESTIONS"]).read_text(encoding="utf-8")

    for index in range(1, 11):
        assert f"## GQ{index:02d} -" in report
    assert "Coverage statement:" in report
    assert "Profile:" in report
    for section in ["## Artifact Inventory", "## Skipped Artifacts", "## Commands Run", "## Fixture Results", "## Residual Risks"]:
        assert section in packet
    assert "## Expected External Verdict Format" in packet
    assert "`ACCEPT`" in packet and "`REDIRECT`" in packet and "`BLOCK`" in packet
    assert "Inventory note:" in packet
    assert f"| `{ARTIFACT_PATHS['ADVERSARIAL_REVIEW_PACKET']}` |" not in packet
    assert "Human decision required:" in open_questions
    assert validate_audit(audit_dir).ok


def test_generate_report_artifacts_rechecks_fresh_artifacts_before_packet(tmp_path: Path) -> None:
    audit_dir = build_validated_audit(tmp_path)
    packet = audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]
    assert packet.exists()
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph.pop("nodes")
    graph_path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")

    try:
        generate_report_artifacts(audit_dir)
    except ReportGateError:
        pass
    else:
        raise AssertionError("ReportGateError was not raised")

    assert not packet.exists()


def test_artifact_inventory_excludes_secret_named_files(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / "REPORT.md").write_text("report", encoding="utf-8")
    (audit_dir / ".env").write_text("PASSWORD=secret", encoding="utf-8")
    (audit_dir / ".ENV").write_text("PASSWORD=secret", encoding="utf-8")
    (audit_dir / "credentials.json").write_text("{}", encoding="utf-8")
    (audit_dir / "SECRET.txt").write_text("secret", encoding="utf-8")
    (audit_dir / "id_rsa").write_text("key", encoding="utf-8")

    names = {name for name, _size, _digest in artifact_inventory(audit_dir)}

    assert names == {"REPORT.md"}


def test_validation_passed_requires_structured_report(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).write_text(
        "# Validation Report\n\n- Status: `pass`\n- Blocker count: `0`\n",
        encoding="utf-8",
    )

    assert validation_passed(audit_dir) is False


def test_validate_rechecks_fresh_artifacts_before_review_packet(tmp_path: Path) -> None:
    audit_dir = build_validated_audit(tmp_path)
    packet = audit_dir / ARTIFACT_PATHS["ADVERSARIAL_REVIEW_PACKET"]
    assert packet.exists()
    graph_path = audit_dir / ARTIFACT_PATHS["GRAPH"]
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph.pop("nodes")
    graph_path.write_text(json.dumps(graph, indent=2) + "\n", encoding="utf-8")

    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=audit_dir.parent)

    assert result.returncode != 0
    assert not packet.exists()
    validation = (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).read_text(encoding="utf-8")
    assert "Blocker count: `0`" not in validation
    assert "graph_schema:" in validation


def test_partial_validate_does_not_emit_final_packet(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path)
    inventory = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert inventory.returncode == 0, inventory.stderr
    audit_dir = repo / "audit"

    result = run_cli("validate", "--audit-dir", str(audit_dir), cwd=repo)

    assert result.returncode == 0, result.stderr
    assert (audit_dir / ARTIFACT_PATHS["VALIDATION_REPORT"]).exists()
    for key in ["REPORT", "REVIEW_LEDGER", "ADVERSARIAL_REVIEW_PACKET"]:
        assert not (audit_dir / ARTIFACT_PATHS[key]).exists()


def test_review_packet_missing_is_blocker_when_run_config_ready_for_review(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).write_text(json.dumps({"ready_for_review": True}) + "\n", encoding="utf-8")
    errors: list[str] = []

    validate_review_packet(audit_dir, errors)

    assert any("ready_for_review is true" in error for error in errors)


def test_review_ledger_rejects_self_acceptance(tmp_path: Path) -> None:
    audit_dir = build_validated_audit(tmp_path)
    ledger = audit_dir / ARTIFACT_PATHS["REVIEW_LEDGER"]
    ledger.write_text(
        "# Review Ledger\n\n"
        "| Artifact | Author | Reviewer | Decision | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| `REPORT.md` | same_agent | same_agent | ACCEPT | synthetic |\n",
        encoding="utf-8",
    )

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("self-acceptance" in error for error in result.errors)


def test_review_ledger_rejects_self_accepted_variant_casefold(tmp_path: Path) -> None:
    audit_dir = build_validated_audit(tmp_path)
    ledger = audit_dir / ARTIFACT_PATHS["REVIEW_LEDGER"]
    ledger.write_text(
        "# Review Ledger\n\n"
        "| Artifact | Author | Reviewer | Decision | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| `REPORT.md` | Same_Agent | same_agent | ACCEPTED | synthetic |\n",
        encoding="utf-8",
    )

    result = validate_audit(audit_dir)

    assert not result.ok
    assert any("self-acceptance" in error for error in result.errors)


def test_report_template_maps_all_goal_questions() -> None:
    template = (PLUGIN_ROOT / "assets" / "templates" / "report.md").read_text(encoding="utf-8")

    for index in range(1, 11):
        assert f"## GQ{index:02d} -" in template
