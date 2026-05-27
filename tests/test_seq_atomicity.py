from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.models import ARTIFACT_PATHS, PLUGIN_ROOT


REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = PLUGIN_ROOT / "tests" / "check_seq_atomicity.py"


def test_seq_atomicity_checker_passes_minimal_plan(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    (plan_dir / "001_seq_good.md").write_text(
        "# Good\n\n"
        "- [ ] Step 001.1 - Complete fields.\n"
        "  - Target: good.\n"
        "  - Refs: test.\n"
        "  - Verify: pass.\n",
        encoding="utf-8",
    )
    output = tmp_path / ARTIFACT_PATHS["SEQ_ATOMICITY_REPORT"]
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--plan-dir", str(plan_dir), "--output", str(output)],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert "Status: `pass`" in output.read_text(encoding="utf-8")


def test_seq_atomicity_checker_fails_missing_refs(tmp_path: Path) -> None:
    plan_dir = tmp_path / "plan"
    plan_dir.mkdir()
    (plan_dir / "001_seq_bad.md").write_text(
        "# Bad\n\n"
        "- [ ] Step 001.1 - Missing refs.\n"
        "  - Target: bad.\n"
        "  - Verify: fail.\n",
        encoding="utf-8",
    )
    output = tmp_path / "audit" / ARTIFACT_PATHS["SEQ_ATOMICITY_REPORT"]

    result = subprocess.run(
        [sys.executable, str(CHECKER), "--plan-dir", str(plan_dir), "--output", str(output)],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    assert "missing Refs:" in output.read_text(encoding="utf-8")
