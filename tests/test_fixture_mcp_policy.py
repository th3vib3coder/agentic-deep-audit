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
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"
RAW_SECRET_MARKERS = ["eyJ", "ghp_", "AKIA", "Bearer abcdefghij", "Abcdef1234567890QRSTuvwx"]


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def copy_fixture(tmp_path: Path, name: str) -> Path:
    repo = tmp_path / name
    shutil.copytree(FIXTURE_ROOT / name, repo)
    return repo


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "agentic_deep_audit.cli", *args], cwd=cwd, env=cli_env(), check=False, text=True, capture_output=True)


def test_mcp_collision_detected_fixture_blocks_generated_config(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "mcp_collision_detected")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    audit_dir = repo / "audit"

    assert result.returncode == 0, result.stderr
    report = audit_dir / ARTIFACT_PATHS["MCP_COLLISION_REPORT"]
    assert report.exists()
    assert "agentic_deep_audit_audit_query" in report.read_text(encoding="utf-8")
    assert not (audit_dir / ARTIFACT_PATHS["MCP_CONFIG"]).exists()
    assert validate_audit(audit_dir).ok


def test_mcp_host_secret_redact_fixture_never_persists_raw_values(tmp_path: Path) -> None:
    repo = copy_fixture(tmp_path, "mcp_host_secret_redact")
    result = run_cli("run", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    audit_dir = repo / "audit"
    report = audit_dir / ARTIFACT_PATHS["MCP_COLLISION_REPORT"]

    assert result.returncode == 0, result.stderr
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    for marker in RAW_SECRET_MARKERS:
        assert marker not in text
    assert "<redacted sha256:" in text
    assert not (audit_dir / ARTIFACT_PATHS["MCP_CONFIG"]).exists()
    assert validate_audit(audit_dir).ok


def test_mcp_secret_fixture_contains_authoritative_raw_markers() -> None:
    payload = json.loads((FIXTURE_ROOT / "mcp_host_secret_redact" / "host_mcp_state.json").read_text(encoding="utf-8"))
    rendered = json.dumps(payload)

    for marker in RAW_SECRET_MARKERS:
        assert marker in rendered
