from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

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


def cards_by_path(cards: list[dict]) -> dict[str, dict]:
    return {str(card.get("path")): card for card in cards if card.get("kind") == "file"}


def test_license_manifest_extracts_root_dependency_and_sbom_skip(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_manifest")

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    payload = load_json(audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"])
    assert payload["summary"]["root_license"] == "MIT"
    assert payload["summary"]["file_denominator"] > 0
    cards = payload["cards"]
    deps = {card["component"]: card for card in cards if card["kind"] == "dependency"}
    assert deps["left-pad"]["declared_license"] == "MIT"
    assert deps["left-pad"]["confidence"] == "medium"
    assert deps["example-copyleft"]["requires_human_decision"] is True
    matrix = (audit_dir / ARTIFACT_PATHS["LICENSE_MATRIX"]).read_text(encoding="utf-8")
    assert "Legal review required for reuse" in matrix
    assert (audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]).exists()
    assert not (audit_dir / ARTIFACT_PATHS["SBOM"]).exists()
    assert validate_audit(audit_dir).ok


def test_package_metadata_root_license_keeps_manifest_evidence(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_manifest")
    (repo / "LICENSE").unlink()

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    summary = load_json(repo / "audit" / ARTIFACT_PATHS["LICENSE_CARDS"])["summary"]
    assert summary["root_license"] == "MIT"
    assert summary["root_detection_method"] == "package_metadata"
    assert summary["root_license_evidence_id"].startswith("ev-")
    assert validate_audit(repo / "audit").ok


def test_file_level_license_cards_cover_denominator_and_skips(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_file_level_mixed")

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    payload = load_json(audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"])
    by_path = cards_by_path(payload["cards"])
    assert by_path["src/with_header.py"]["declared_license"] == "Apache-2.0"
    assert by_path["src/with_header.py"]["confidence"] == "high"
    assert by_path["src/no_header.py"]["skipped_reason"] == "no file-level SPDX header; root license fallback needs review"
    assert by_path["generated/client.py"]["detection_method"] == "skipped:generated_file"
    assert by_path["vendor/vendored.js"]["detection_method"] == "skipped:vendored_file"
    denominator = [card for card in by_path.values() if not str(card["detection_method"]).startswith("skipped:")]
    assert payload["summary"]["file_denominator"] == len(denominator)
    assert validate_audit(audit_dir).ok


def test_license_validation_rejects_missing_denominator_card(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_file_level_mixed")
    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    path = audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"]
    payload = load_json(path)
    payload["cards"] = [card for card in payload["cards"] if card.get("path") != "src/no_header.py"]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("missing file coverage" in error for error in validation.errors)


def test_binary_artifacts_respect_consent_and_mismatch_counts(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "binary_artifacts")

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    payload = load_json(audit_dir / ARTIFACT_PATHS["BINARY_ARTIFACTS"])
    summary = payload["summary"]
    assert summary["blob_count"] == 4
    assert summary["native_binary_count"] >= 2
    assert summary["mime_mismatch_count"] == 1
    assert summary["triage_consent"] is False
    assert summary["triage_triggered"] is False
    assert all(item["triage_triggered"] is False and item["requires_operator_consent"] is True for item in payload["artifacts"])
    assert validate_audit(audit_dir).ok


def test_binary_triage_only_triggers_with_operator_consent(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "binary_artifacts")
    config = repo / "audit.config.yaml"
    config.write_text(config.read_text(encoding="utf-8").replace("binary_triage_consent: false", "binary_triage_consent: true"), encoding="utf-8")

    result = run_cli("risk", "--config", str(config), cwd=repo)

    assert result.returncode == 0, result.stderr
    payload = load_json(repo / "audit" / ARTIFACT_PATHS["BINARY_ARTIFACTS"])
    assert payload["summary"]["triage_consent"] is True
    assert payload["summary"]["triage_triggered"] is True
    assert all(item["triage_triggered"] is True and item["requires_operator_consent"] is False for item in payload["artifacts"])
    assert validate_audit(repo / "audit").ok


def test_sbom_validation_requires_exactly_one_artifact(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_manifest")
    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    (audit_dir / ARTIFACT_PATHS["SBOM"]).write_text(json.dumps({"bomFormat": "CycloneDX"}) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("exactly one of SBOM.cdx.json or SBOM_SKIPPED.md" in error for error in validation.errors)


def test_sbom_missing_both_fails_and_stale_sbom_is_replaced(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "license_manifest")
    audit_dir = repo / "audit"
    audit_dir.mkdir()
    (audit_dir / ARTIFACT_PATHS["SBOM"]).write_text(json.dumps({"bomFormat": "CycloneDX", "stale": True}) + "\n", encoding="utf-8")
    first = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert first.returncode == 0, first.stderr
    assert not (audit_dir / ARTIFACT_PATHS["SBOM"]).exists()
    assert (audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]).exists()

    (audit_dir / ARTIFACT_PATHS["SBOM_SKIPPED"]).unlink()
    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("exactly one of SBOM.cdx.json or SBOM_SKIPPED.md" in error for error in validation.errors)


def test_binary_validation_recomputes_summary_counts(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "binary_artifacts")
    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    path = repo / "audit" / ARTIFACT_PATHS["BINARY_ARTIFACTS"]
    payload = load_json(path)
    payload["summary"]["total_binary_bytes"] = 999
    payload["summary"]["native_binary_count"] = 999
    payload["summary"]["mime_mismatch_count"] = 999
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_audit(repo / "audit")

    assert not validation.ok
    assert any("total_binary_bytes mismatch" in error for error in validation.errors)
    assert any("native_binary_count mismatch" in error for error in validation.errors)
    assert any("mime_mismatch_count mismatch" in error for error in validation.errors)
