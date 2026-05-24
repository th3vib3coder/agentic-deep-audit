from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_deep_audit.audit_evidence import sha256_range, validate_claims_reach_evidence
from agentic_deep_audit.audit_validate import validate_audit, validate_evidence_index_artifact
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures" / "python_basic"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def prepare_fixture(tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(FIXTURE_ROOT, target)
    (target / "assets" / "logo.bin").write_bytes(b"\x00\x01\x02")
    (target / "docs").mkdir()
    (target / "docs" / "crlf.txt").write_bytes(b"alpha\r\nbeta\r\n")
    git_dir = target / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
    return target


def write_config(repo: Path) -> Path:
    config = repo / "audit.config.yaml"
    config.write_text(
        "\n".join(
            [
                'schema_version: "1.0"',
                "repo:",
                '  kind: "local"',
                '  path: "."',
                "  github: null",
                'profile: "minimal"',
                'mode: "source-audit"',
                'output_dir: "audit"',
                "scope_filters:",
                '  include: ["**/*"]',
                '  exclude: [".git/**", "node_modules/**"]',
                'target_context: "MIT downstream"',
                "binary_triage_consent: false",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return config


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def run_inventory(tmp_path: Path) -> tuple[Path, Path]:
    repo = prepare_fixture(tmp_path)
    config = write_config(repo)
    result = run_cli("inventory", "--config", str(config), cwd=repo)
    assert result.returncode == 0, result.stderr
    return repo, repo / "audit"


def git_available() -> bool:
    return shutil.which("git") is not None


def run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True)


def prepare_git_fixture(tmp_path: Path) -> Path:
    if not git_available():
        pytest.skip("git unavailable")
    repo = tmp_path / "git-repo"
    shutil.copytree(FIXTURE_ROOT, repo)
    (repo / "assets" / "logo.bin").write_bytes(b"\x00\x01\x02")
    write_config(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "fixture@example.com")
    run_git(repo, "config", "user.name", "Fixture")
    run_git(repo, "add", ".")
    run_git(repo, "commit", "-m", "initial")
    return repo


def load_evidence(audit_dir: Path) -> dict:
    return json.loads((audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]).read_text(encoding="utf-8"))


def by_path(evidence_index: dict) -> dict[str, dict]:
    return {item["path"]: item for item in evidence_index["evidence"]}


def test_evidence_ids_are_stable_zero_padded_and_recorded(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    first = load_evidence(audit_dir)
    second = load_evidence(audit_dir)

    ids = [item["id"] for item in first["evidence"]]
    assert ids == [f"ev-{index:06d}" for index in range(1, len(ids) + 1)]
    assert ids == [item["id"] for item in second["evidence"]]
    assert first["allocator"]["mapping"][0]["evidence_id"] == "ev-000001"


def test_crlf_text_evidence_preserves_line_metadata_and_byte_seek(tmp_path: Path) -> None:
    repo, audit_dir = run_inventory(tmp_path)
    evidence = by_path(load_evidence(audit_dir))["docs/crlf.txt"]
    data = (repo / "docs" / "crlf.txt").read_bytes()

    assert evidence["kind"] == "file_line"
    assert evidence["line_ending_original"] == "CRLF"
    assert evidence["start_line"] == 1
    assert evidence["end_line"] == 2
    assert evidence["start_byte"] == 0
    assert evidence["end_byte"] == len(data)
    assert sha256_range(data, evidence["start_byte"], evidence["end_byte"]) == evidence["sha256"]
    assert hashlib.sha256(data[evidence["start_byte"] : evidence["end_byte"]]).hexdigest() == evidence["sha256"]


def test_binary_evidence_has_byte_range_and_no_line_range(tmp_path: Path) -> None:
    repo, audit_dir = run_inventory(tmp_path)
    evidence = by_path(load_evidence(audit_dir))["assets/logo.bin"]
    data = (repo / "assets" / "logo.bin").read_bytes()

    assert evidence["kind"] == "file_whole"
    assert evidence["binary_safe"] is True
    assert "start_line" not in evidence
    assert "end_line" not in evidence
    assert evidence["start_byte"] == 0
    assert evidence["end_byte"] == len(data)
    assert evidence["sha256"] == hashlib.sha256(data).hexdigest()


def test_tampered_evidence_hash_fails_validation(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    payload["evidence"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("sha256 mismatch" in error for error in validation.errors)


def test_evidence_validation_rejects_file_line_missing_byte_range(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    text_item = next(item for item in payload["evidence"] if item["kind"] == "file_line")
    text_item.pop("start_byte")
    text_item.pop("end_byte")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("requires start_byte and end_byte" in error for error in validation.errors)


def test_evidence_validation_rejects_binary_safe_missing_byte_range(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    binary_item = by_path(payload)["assets/logo.bin"]
    binary_item.pop("start_byte")
    binary_item.pop("end_byte")
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("requires start_byte and end_byte" in error for error in validation.errors)


def test_claim_without_reachable_evidence_id_fails_resolution_and_validation(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    claim = {"claim_id": "cl-000001", "claim_type": "architecture", "statement": "x", "status": "observed", "confidence": "high", "evidence_ids": ["ev-999999"], "limitations": []}

    assert validate_claims_reach_evidence([claim], payload)
    payload["claims"] = [claim]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("unreachable evidence ids" in error for error in validation.errors)


def test_cross_artifact_evidence_ids_must_resolve(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    risk_findings = {
        "schema_version": "1.0",
        "findings": [
            {
                "finding_id": "risk-1",
                "category": "dependency_cve",
                "severity": "high",
                "confidence": "high",
                "evidence_ids": ["ev-999999"],
                "source_kind": "external_tool",
                "recommendation": "upgrade",
                "requires_human_decision": False,
            }
        ],
    }
    (audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"]).write_text(json.dumps(risk_findings, indent=2) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("RISK_FINDINGS.json.findings[0].evidence_ids references unreachable evidence id" in error for error in validation.errors)


def test_cross_artifact_evidence_ids_reject_blank_or_non_string(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    risk_findings = {
        "schema_version": "1.0",
        "findings": [
            {
                "finding_id": "risk-1",
                "category": "dependency_cve",
                "severity": "high",
                "confidence": "high",
                "evidence_ids": ["", None],
                "source_kind": "external_tool",
                "recommendation": "upgrade",
                "requires_human_decision": False,
            }
        ],
    }
    (audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"]).write_text(json.dumps(risk_findings, indent=2) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("contains invalid evidence id: ''" in error for error in validation.errors)
    assert any("contains invalid evidence id: None" in error for error in validation.errors)


@pytest.mark.parametrize("unsafe_path", ["../outside.txt", "/outside.txt", "\\outside.txt", "a:b.txt"])
def test_evidence_validation_rejects_unsafe_paths(tmp_path: Path, unsafe_path: str) -> None:
    _, audit_dir = run_inventory(tmp_path)
    path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    provenance_path = audit_dir / ARTIFACT_PATHS["PROVENANCE"]
    payload = load_evidence(audit_dir)
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    fake_commit = "a" * 40
    payload["repo"]["commit"] = fake_commit
    payload["evidence"][0]["path"] = unsafe_path
    provenance["git"]["commit"] = fake_commit
    provenance["git"]["limitations"] = []
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("unsafe source path" in error for error in validation.errors)


def test_git_provenance_commit_is_synced_to_evidence_index(tmp_path: Path) -> None:
    repo = prepare_git_fixture(tmp_path)

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    evidence = load_evidence(repo / "audit")
    provenance = json.loads((repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8"))
    assert evidence["repo"]["commit"] == provenance["git"]["commit"]
    assert len(evidence["repo"]["commit"]) == 40


def test_evidence_validation_rejects_repo_path_different_from_provenance_target(tmp_path: Path) -> None:
    repo, audit_dir = run_inventory(tmp_path)
    mirror = tmp_path / "mirror"
    shutil.copytree(repo, mirror, ignore=shutil.ignore_patterns("audit"))
    evidence_path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    payload["repo"]["path"] = str(mirror)
    evidence_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("repo.path differs from PROVENANCE.json target path" in error for error in validation.errors)


def test_evidence_validation_rejects_commit_presence_mismatch_with_provenance(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)
    evidence_path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    payload = load_evidence(audit_dir)
    payload["repo"]["commit"] = "b" * 40
    evidence_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("repo.commit differs from PROVENANCE.json git.commit" in error for error in validation.errors)


def test_same_commit_changed_byte_hash_is_validation_blocker(tmp_path: Path) -> None:
    repo, audit_dir = run_inventory(tmp_path)
    evidence_path = audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"]
    provenance_path = audit_dir / ARTIFACT_PATHS["PROVENANCE"]
    evidence = load_evidence(audit_dir)
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    fake_commit = "a" * 40
    evidence["repo"]["commit"] = fake_commit
    provenance["git"]["commit"] = fake_commit
    provenance["git"]["limitations"] = []
    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    (repo / "README.md").write_text("# Mutated\n", encoding="utf-8")
    validation = validate_evidence_index_artifact(audit_dir)

    assert not validation.ok
    assert any("evidence drift for same provenance input" in error for error in validation.errors)


def test_full_audit_validation_checks_evidence_ranges(tmp_path: Path) -> None:
    _, audit_dir = run_inventory(tmp_path)

    validation = validate_audit(audit_dir)

    assert validation.ok, validation.errors
