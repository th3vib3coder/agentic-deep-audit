from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT
from agentic_deep_audit.sanitize import sanitize_markdown


SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURE_ROOT = PLUGIN_ROOT / "tests" / "fixtures"


def test_blocked_command_attempt_fixture_logs_non_empty_attempt(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    manifest = json.loads((FIXTURE_ROOT / "blocked_command_attempt" / "package.json").read_text(encoding="utf-8"))
    command = ["npm", "run", "dangerous", "--token=ghp_abcdefghijklmnop123456"]
    assert manifest["scripts"]["dangerous"]

    result = subprocess.run(
        [sys.executable, str(PLUGIN_ROOT / "hooks" / "pre_tool_policy.py"), "--origin", "target_repo_manifest", "--audit-dir", str(audit_dir), "--", *command],
        cwd=PLUGIN_ROOT,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    attempts = json.loads((audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"]).read_text(encoding="utf-8"))

    assert result.returncode == 1
    assert attempts["attempts"]
    assert attempts["attempts"][0]["policy_rule"] == "target_repo_manifest_no_exec"
    assert attempts["attempts"][0]["redacted_args"][-1] == "<redacted>"


def test_markdown_prompt_injection_fixture_is_blocked_from_context() -> None:
    readme = (FIXTURE_ROOT / "markdown_prompt_injection" / "README.md").read_text(encoding="utf-8")
    agents = (FIXTURE_ROOT / "markdown_prompt_injection" / "AGENTS.md").read_text(encoding="utf-8")

    readme_result = sanitize_markdown("README.md", readme, evidence_id="ev-readme")
    agents_result = sanitize_markdown("AGENTS.md", agents, evidence_id="ev-agents")

    assert readme_result.decision == "blocked_from_llm_context"
    assert {flag["kind"] for flag in readme_result.flagged_ranges} >= {"hidden_tag", "override_marker"}
    assert agents_result.decision == "blocked_from_llm_context"
    assert agents_result.sanitized_text.startswith("> ")
