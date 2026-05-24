from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.audit_reuse import run_reuse
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


def run_reuse_fixture(tmp_path: Path) -> Path:
    repo = copy_fixture(tmp_path, "performance_quality_project")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo / "audit"


def test_run_command_wires_contextual_reuse_outputs(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)

    cards = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"])
    special = load_json(audit_dir / ARTIFACT_PATHS["SPECIAL_IMPLEMENTATIONS"])
    map_text = (audit_dir / ARTIFACT_PATHS["REUSE_MAP"]).read_text(encoding="utf-8")

    assert cards["target_context"]["allowed_languages"] == ["python"]
    assert cards["scoring_input_sources"]["target_context"] == ARTIFACT_PATHS["RUN_CONFIG"]
    assert cards["cards"]
    assert {card["candidate_id"] for card in cards["cards"]} == {candidate["candidate_id"] for candidate in special["candidates"]}
    assert "Legal caveat" in map_text
    assert "## Target Context" in map_text
    assert validate_audit(audit_dir).ok


def test_ambiguous_license_cannot_produce_unconditional_adopt(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    cards = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"])

    assert cards["cards"]
    for card in cards["cards"]:
        assert card["license_status"] == "unknown"
        assert card["requires_human_decision"] is True
        assert card["decision"] != "adopt"
        assert "license_unknown" in card["score_inputs"]["requires_human_reasons"]


def test_strong_copyleft_spdx_variant_forces_human_decision(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    license_path = audit_dir / ARTIFACT_PATHS["LICENSE_CARDS"]
    licenses = load_json(license_path)
    licenses["summary"]["root_license"] = "GPL-3.0-only"
    license_path.write_text(json.dumps(licenses, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    run_reuse(load_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]), audit_dir)
    cards = load_json(audit_dir / ARTIFACT_PATHS["REUSE_CARDS"])

    assert cards["cards"]
    for card in cards["cards"]:
        assert card["license_status"] == "conflict"
        assert card["requires_human_decision"] is True
        assert card["decision"] != "adopt"
        assert "strong_copyleft_conflict" in card["score_inputs"]["requires_human_reasons"]
    assert validate_audit(audit_dir).ok


def test_validator_rejects_missing_reuse_card_for_candidate(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    cards_path = audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]
    payload = load_json(cards_path)
    payload["cards"] = payload["cards"][1:]
    cards_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("missing reuse card or skipped reason" in error for error in validation.errors)


def test_validator_rejects_tampered_unknown_license_adopt_false_pass(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    cards_path = audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]
    payload = load_json(cards_path)
    card = payload["cards"][0]
    card["license_status"] = "unknown"
    card["decision"] = "adopt"
    card["recommendation"] = "adopt"
    card["requires_human_decision"] = False
    card["score_inputs"]["requires_human_reasons"] = []
    cards_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("structural blocker" in error for error in validation.errors)


def test_validator_rejects_missing_reuse_caveats(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    cards_path = audit_dir / ARTIFACT_PATHS["REUSE_CARDS"]
    payload = load_json(cards_path)
    payload["cards"][0]["legal_caveat"] = ""
    cards_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("legal_caveat" in error for error in validation.errors)


def test_validator_rejects_invalid_run_config_target_context(tmp_path: Path) -> None:
    audit_dir = run_reuse_fixture(tmp_path)
    run_config_path = audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]
    run_config = load_json(run_config_path)
    run_config["target_context"]["allowed_languages"] = "python"
    run_config_path.write_text(json.dumps(run_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("target_context invalid" in error for error in validation.errors)


def test_run_dry_run_lists_reuse_artifacts(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "performance_quality_project")

    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), "--dry-run", cwd=repo)

    assert result.returncode == 0, result.stderr
    planned = set(json.loads(result.stdout)["planned_artifacts"])
    assert {ARTIFACT_PATHS["REUSE_CARDS"], ARTIFACT_PATHS["REUSE_MAP"]} <= planned
