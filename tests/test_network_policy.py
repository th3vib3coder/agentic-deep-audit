from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT
from agentic_deep_audit.policy import decide_network


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"


def test_network_precedence_check_fixture_cases() -> None:
    policy = json.loads((FIXTURE_ROOT / "network_precedence_check" / ".network_policy.json").read_text(encoding="utf-8"))

    denied_subdomain = decide_network("blocked.example.org", policy=policy)
    exact_allowed = decide_network("api.example.com", policy=policy)
    source_payload = decide_network("api.example.com", payload="def leak(): pass", policy=policy)
    missing_policy = decide_network("api.example.com", policy=None)

    assert denied_subdomain.decision == "block"
    assert denied_subdomain.policy_rule == "denied:blocked.example.org"
    assert exact_allowed.decision == "allow"
    assert exact_allowed.policy_rule == "allowed:api.example.com"
    assert source_payload.decision == "block"
    assert source_payload.policy_rule == "send_source_code_false"
    assert missing_policy.decision == "block"
    assert missing_policy.policy_rule == "missing_policy"


def test_absent_network_policy_bootstrap_records_skipped(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE_ROOT / "network_precedence_check", repo)
    (repo / ".network_policy.json").unlink()
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", "inventory", "--config", str(repo / "audit.config.yaml")],
        cwd=repo,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    tool_status = json.loads((repo / "audit" / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))

    assert result.returncode == 0, result.stderr
    assert any(tool["tool"] == "network_policy" and tool["status"] == "skipped" for tool in tool_status["tools"])
