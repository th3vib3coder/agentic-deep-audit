from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_deep_audit.audit_license_binary as license_binary
from agentic_deep_audit.audit_license_binary import LICENSE_REUSE_COMPATIBLE, binary_artifacts, heuristic_license_from_text, license_cards, spdx_from_text
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
    assert summary["mime_mismatch_count"] == 0
    assert summary["triage_consent"] is False
    assert summary["triage_triggered"] is False
    assert all(item["triage_triggered"] is False and item["requires_operator_consent"] is True for item in payload["artifacts"])
    assert all("not read" in item["skipped_reason"] for item in payload["artifacts"])
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
    assert payload["summary"]["mime_mismatch_count"] == 1
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


def test_heuristic_detects_copyleft_licenses_not_unknown() -> None:
    # C7-01: copyleft families must be classified (never "unknown"), and must NOT be reuse-compatible
    # — otherwise a GPL/AGPL/LGPL/MPL repo is silently treated as conflict-free (legal hazard).
    gpl3, _ = heuristic_license_from_text("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007")
    gpl2, _ = heuristic_license_from_text("GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991")
    agpl, _ = heuristic_license_from_text("GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007")
    lgpl, _ = heuristic_license_from_text("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007")
    mpl, _ = heuristic_license_from_text("Mozilla Public License Version 2.0")

    assert (gpl3, gpl2, agpl, lgpl, mpl) == ("GPL-3.0", "GPL-2.0", "AGPL-3.0", "LGPL-3.0", "MPL-2.0")
    for spdx in (gpl3, gpl2, agpl, lgpl, mpl):
        assert spdx not in LICENSE_REUSE_COMPATIBLE

    # permissive families still detected and not conflated (ISC vs MIT)
    assert heuristic_license_from_text("MIT License\n\nPermission is hereby granted, free of charge, to any person")[0] == "MIT"
    assert heuristic_license_from_text("ISC License\n\nPermission to use, copy, modify, and/or distribute this software")[0] == "ISC"
    assert heuristic_license_from_text("Redistribution and use ... Neither the name of the copyright holder")[0] == "BSD-3-Clause"
    assert heuristic_license_from_text("totally proprietary, all rights reserved")[0] is None


def test_spdx_identifier_preserves_full_expression() -> None:
    # C7-02: OR/AND/WITH operators and exceptions are legally significant and must survive.
    assert spdx_from_text("// SPDX-License-Identifier: Apache-2.0 OR MIT\n") == "Apache-2.0 OR MIT"
    assert spdx_from_text("/* SPDX-License-Identifier: GPL-2.0-only WITH Classpath-exception-2.0 */") == "GPL-2.0-only WITH Classpath-exception-2.0"
    assert spdx_from_text("# SPDX-License-Identifier: (Apache-2.0 AND MIT)\n") == "(Apache-2.0 AND MIT)"
    # single-license header unchanged (no regression)
    assert spdx_from_text("# SPDX-License-Identifier: MIT\n") == "MIT"


def test_license_cards_reject_unsafe_repo_relative_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("# SPDX-License-Identifier: GPL-3.0\n", encoding="utf-8")
    file_index = {"repo": {"path": str(repo)}, "records": [{"path": "../outside.py", "kind": "code", "binary": False, "size_bytes": 1}]}

    payload = license_cards({}, tmp_path / "audit", file_index, {"records": []}, repo, {"../outside.py": "ev-000001"})

    assert payload["cards"][0]["declared_license"] is None
    assert payload["cards"][0]["detection_method"] == "skipped:unsafe_repository_path"
    assert "unsafe repository path" in payload["cards"][0]["skipped_reason"]


def test_root_license_reports_nested_incompatible_license(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    nested = repo / "packages" / "gpl"
    nested.mkdir(parents=True)
    (repo / "LICENSE").write_text("MIT License\n\nPermission is hereby granted, free of charge, to any person\n", encoding="utf-8")
    (nested / "LICENSE").write_text("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n", encoding="utf-8")
    file_index = {
        "repo": {"path": str(repo)},
        "records": [
            {"path": "LICENSE", "kind": "docs", "binary": False, "size_bytes": 1},
            {"path": "packages/gpl/LICENSE", "kind": "docs", "binary": False, "size_bytes": 1},
        ],
    }

    payload = license_cards({}, tmp_path / "audit", file_index, {"records": []}, repo, {"LICENSE": "ev-000001", "packages/gpl/LICENSE": "ev-000002"})
    summary = payload["summary"]

    assert summary["root_license"] == "MIT"
    assert any(item["scope"] == "subtree_root" and item["declared_license"] == "GPL-3.0" for item in summary["license_file_detections"])
    assert summary["root_license_conflict_count"] == 1
    assert summary["incompatible_license_files"][0]["path"] == "packages/gpl/LICENSE"


def test_binary_triage_without_consent_does_not_read_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden_read(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("binary bytes were read without consent")

    monkeypatch.setattr(license_binary, "read_bytes_capped", forbidden_read)
    payload = binary_artifacts(
        {"binary_triage_consent": False},
        {"records": [{"path": "artifact.exe", "binary": True, "size_bytes": 123}]},
        tmp_path,
        {"artifact.exe": "ev-000001"},
    )

    artifact = payload["artifacts"][0]
    assert artifact["triage_triggered"] is False
    assert artifact["requires_operator_consent"] is True
    assert artifact["mime_detected"] is None
    assert "not read" in artifact["skipped_reason"]
