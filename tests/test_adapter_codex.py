"""Adapter tests for the Codex boundary doc and manifest/skill routing (S-C01)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from agentic_deep_audit.models import PLUGIN_ROOT

CODEX_DOC = PLUGIN_ROOT / "docs" / "adapters" / "codex.md"
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


@pytest.mark.codex_adapter
def test_codex_adapter_doc_exists_and_has_nine_fields() -> None:
    text = CODEX_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"docs/adapters/codex.md missing field sections: {missing}"
    # SD-2 boundary: Codex is one co-equal adapter, not required for the CLI/package.
    assert "codex is one adapter" in lowered
    assert "not required for cli" in lowered


@pytest.mark.codex_adapter
def test_codex_manifest_and_skill_routing() -> None:
    manifest_path = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
    skill_path = PLUGIN_ROOT / "skills" / "deep-repo-audit" / "SKILL.md"
    assert manifest_path.exists()
    assert skill_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    skills = manifest.get("skills", [])
    assert any(
        entry.get("name") == "deep-repo-audit"
        and entry.get("path") == "skills/deep-repo-audit/SKILL.md"
        for entry in skills
    ), "plugin.json must route to the deep-repo-audit skill"


def _decorator_names_codex_mark(decorator: ast.expr) -> bool:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return isinstance(target, ast.Attribute) and target.attr == "codex_adapter"


@pytest.mark.codex_adapter
def test_codex_tests_are_marked_codex_adapter() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    missing = [
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("test_")
        and not any(_decorator_names_codex_mark(dec) for dec in node.decorator_list)
    ]
    assert not missing, f"every test in test_adapter_codex.py must carry @pytest.mark.codex_adapter; missing: {missing}"
