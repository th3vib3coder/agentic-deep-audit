"""Adapter tests for the Claude Code adapter doc and existing manifest/hook contract (S-C02)."""

from __future__ import annotations

import json
import re

from agentic_deep_audit.models import PLUGIN_ROOT

CLAUDE_DOC = PLUGIN_ROOT / "docs" / "adapters" / "claude-code.md"
NINE_FIELDS = (
    "adapter id",
    "user entry command",
    "required files",
    "optional files",
    "output directory",
    "security model",
    "expected skipped/deferred behavior",
    "validation command",
    "ownership of docs/tests",
)


def test_claude_code_adapter_doc_exists_and_has_nine_fields() -> None:
    text = CLAUDE_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"docs/adapters/claude-code.md missing field sections: {missing}"


def test_claude_code_doc_has_runbook_and_safety() -> None:
    text = CLAUDE_DOC.read_text(encoding="utf-8")
    lowered = text.lower()
    assert "## runbook" in lowered
    runbook = re.search(r"##\s+runbook\b(.*?)(?=\n##\s|\Z)", lowered, re.DOTALL)
    assert runbook is not None
    ordered_steps = re.findall(r"(?m)^\s*\d+\.", runbook.group(1))
    assert len(ordered_steps) >= 3, "Runbook must contain at least three ordered steps"
    assert "claude code" in lowered
    assert "no-exec" in lowered or "no exec" in lowered
    assert "external review" in lowered or "handoff" in lowered
    for artifact in ("VALIDATION_REPORT.md", "EVIDENCE_INDEX.json", "RUN_CONFIG.json"):
        assert artifact in text, f"doc must list expected artifact {artifact}"
    assert "claude code is one adapter" in lowered
    assert "not required for cli" in lowered


def test_claude_plugin_manifest_points_to_hooks_json() -> None:
    manifest_path = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
    hooks_path = PLUGIN_ROOT / "hooks" / "hooks.json"
    assert manifest_path.exists()
    assert hooks_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.get("hooks", {}).get("settings") == "hooks/hooks.json"


def test_claude_code_doc_has_no_private_plan_reference() -> None:
    text = CLAUDE_DOC.read_text(encoding="utf-8")
    forbidden = ("piano_doc", "009_review_ledger", "006_validation_review_and_release_gates", "operator_go", "C:\\Users")
    present = [token for token in forbidden if token in text]
    assert not present, f"public doc must not reference private tokens: {present}"
