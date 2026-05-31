from __future__ import annotations

import subprocess
import sys
import os
from pathlib import Path

import pytest

from agentic_deep_audit.gate import GATE_POLICY as RUNTIME_GATE_POLICY
from agentic_deep_audit.gate import decide_path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = Path(__file__).resolve().parents[1] / "src"
PROJECT_SURFACE_PATTERNS = [
    ".claude-plugin/**",
    ".codex-plugin/**",
    ".github/**",
    "assets/**",
    "docs/**",
    "hooks/**",
    "policies/**",
    "skills/**",
    "src/**",
    "tests/**",
    "README.md",
    "RELEASE_CHECKLIST.md",
    "REVIEW*.md",
    "pyproject.toml",
]
GATE_POLICY: dict[str, list[str]] = {
    "implementation_realign": [],
    "operator_go": PROJECT_SURFACE_PATTERNS,
}


def write_ledger(tmp_path: Path, gate: str) -> Path:
    ledger = tmp_path / "ledger.md"
    ledger.write_text(f"# Ledger\n\nStato corrente: `{gate}`.\n", encoding="utf-8")
    return ledger


def subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


@pytest.mark.parametrize(
    ("gate", "path", "expected"),
    [
        ("claude_packet_ready", "src/agentic_deep_audit/x.py", False),
        ("operator_go", "src/agentic_deep_audit/x.py", True),
        ("implementation_external_accept", "src/agentic_deep_audit/x.py", False),
    ],
)
def test_policy_table(gate: str, path: str, expected: bool) -> None:
    assert "src/**" in GATE_POLICY["operator_go"]
    assert GATE_POLICY["implementation_realign"] == []
    assert RUNTIME_GATE_POLICY == GATE_POLICY
    assert decide_path(gate, path).allowed is expected


def test_shipped_defaults_carry_no_private_planning_paths() -> None:
    import agentic_deep_audit.gate as gate_module

    # Shipped defaults gate only the project's own surface; no private planning glob ships.
    assert gate_module.GATE_POLICY["implementation_realign"] == []
    assert tuple(gate_module.SENSITIVE_PATHS) == tuple(PROJECT_SURFACE_PATTERNS)


def test_planning_surface_is_configurable_at_runtime() -> None:
    surface = ["planning_area/**"]
    policy = {"implementation_realign": surface, "operator_go": list(PROJECT_SURFACE_PATTERNS)}
    sensitive = tuple(PROJECT_SURFACE_PATTERNS) + tuple(surface)
    # A configured planning surface is gated by implementation_realign...
    assert decide_path("implementation_realign", "planning_area/seq.md", sensitive_paths=sensitive, gate_policy=policy).allowed is True
    # ...denied under operator_go (wrong gate)...
    assert decide_path("operator_go", "planning_area/seq.md", sensitive_paths=sensitive, gate_policy=policy).allowed is False
    # ...and outside the shipped gated surface when unconfigured.
    assert decide_path("operator_go", "planning_area/seq.md").allowed is True


def test_cli_reports_current_gate_and_blocks_without_operator_go(tmp_path: Path) -> None:
    ledger = write_ledger(tmp_path, "implementation_external_accept")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentic_deep_audit.gate",
            "check-paths",
            "--repo-root",
            str(REPO_ROOT),
            "--ledger",
            str(ledger),
            "--base",
            "HEAD",
            "--path",
            "src/agentic_deep_audit/x.py",
        ],
        check=False,
        env=subprocess_env(),
        text=True,
        capture_output=True,
    )

    assert result.returncode == 1
    assert "current gate: implementation_external_accept" in result.stdout
    assert "DENY src/agentic_deep_audit/x.py" in result.stdout


def test_cli_allows_project_surface_when_operator_go_is_recorded(tmp_path: Path) -> None:
    ledger = write_ledger(tmp_path, "operator_go")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentic_deep_audit.gate",
            "check-paths",
            "--repo-root",
            str(REPO_ROOT),
            "--ledger",
            str(ledger),
            "--base",
            "HEAD",
            "--path",
            "src/agentic_deep_audit/x.py",
        ],
        check=False,
        env=subprocess_env(),
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0
    assert "current gate: operator_go" in result.stdout
    assert "ALLOW src/agentic_deep_audit/x.py" in result.stdout
