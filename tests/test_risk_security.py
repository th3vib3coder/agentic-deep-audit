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
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def copy_fixture(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURES / name, repo)
    return repo


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_mixed_risky_emits_suspicious_supply_chain_and_report(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "mixed_risky")

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    suspicious = load_json(audit_dir / ARTIFACT_PATHS["SUSPICIOUS_BEHAVIORS"])
    kinds = {item["kind"] for item in suspicious["behaviors"]}
    assert {"eval", "exec", "postinstall", "network_call", "dynamic_import", "obfuscation", "binary_drop", "secret_pressure"} <= kinds
    assert all(item["evidence_ids"] and item["recommendation"] for item in suspicious["behaviors"])
    risks = load_json(audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"])
    assert risks["findings"] == []
    assert "not promoted without external tool confirmation" in " ".join(risks["limitations"])
    supply = (audit_dir / ARTIFACT_PATHS["SUPPLY_CHAIN_SIGNALS"]).read_text(encoding="utf-8")
    for signal in ["typosquatting", "dependency_confusion", "starjacking", "maintainer_compromise", "yanked_or_deprecated", "lifecycle_downloads"]:
        assert f"| {signal} |" in supply
    assert "| typosquatting | observed | low | ev-" in supply
    report = (audit_dir / ARTIFACT_PATHS["RISK_REPORT"]).read_text(encoding="utf-8")
    assert "cannot claim absence of vulnerabilities" in report
    assert "External vulnerability tools skipped" in report
    assert validate_audit(audit_dir).ok


def test_agentic_injection_emits_taxonomy_and_lists_scanned_files(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "agentic_injection")

    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    agentic = load_json(audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"])
    codes = {finding["code"] for finding in agentic["findings"]}
    assert {"E004", "W015"} <= codes
    report = (audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY"]).read_text(encoding="utf-8")
    for name in ["AGENTS.md", "CLAUDE.md", "GEMINI.md"]:
        assert name in report
    assert validate_audit(audit_dir).ok


def test_risk_validation_rejects_unconfirmed_heuristic_source_kind(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "mixed_risky")
    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    evidence = load_json(audit_dir / ARTIFACT_PATHS["EVIDENCE_INDEX"])["evidence"][0]["id"]
    path = audit_dir / ARTIFACT_PATHS["RISK_FINDINGS"]
    payload = load_json(path)
    payload["findings"] = [
        {
            "finding_id": "risk-000001",
            "category": "heuristic_eval",
            "severity": "high",
            "confidence": "medium",
            "evidence_ids": [evidence],
            "source_kind": "heuristic",
            "recommendation": "confirm with external tool before promotion",
            "requires_human_decision": True,
        }
    ]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("invalid source_kind" in error for error in validation.errors)


def test_agentic_validation_rejects_unknown_code_and_report_drift(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "agentic_injection")
    result = run_cli("risk", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit"
    path = audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY_FINDINGS"]
    payload = load_json(path)
    payload["findings"][0]["code"] = "X999"
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    report_path = audit_dir / ARTIFACT_PATHS["AGENTIC_SECURITY"]
    report_path.write_text(report_path.read_text(encoding="utf-8").replace("AGENTS.md", "AGENTS_REDACTED.md"), encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("unknown code" in error for error in validation.errors)
    assert any("missing scanned file: AGENTS.md" in error for error in validation.errors)
