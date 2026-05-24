from __future__ import annotations

import json
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
GENERATED_NAMES = {".git", ".pytest_cache", "__pycache__"}


def test_plugin_manifest_contract() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))

    assert manifest["name"] == "agentic-deep-audit"
    assert manifest["version"] == "0.1.0"
    assert manifest["skills"][0]["path"] == "skills/deep-repo-audit/SKILL.md"
    assert manifest["permissions"]["network"] == "none"


def test_python_package_scaffold() -> None:
    init_file = PLUGIN_ROOT / "src" / "agentic_deep_audit" / "__init__.py"

    assert init_file.exists()
    assert init_file.read_text(encoding="utf-8") == ""


def test_pyproject_metadata_contract() -> None:
    pyproject = (PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "agentic-deep-audit"' in pyproject
    assert 'requires-python = ">=3.10"' in pyproject
    assert "jsonschema>=4.0" in pyproject
    assert 'deep-audit = "agentic_deep_audit.cli:main"' in pyproject


def test_scaffold_directories_are_documented() -> None:
    expected = [
        "hooks/README.md",
        "policies/README.md",
        "assets/templates/README.md",
        "tests/fixtures/README.md",
    ]

    for relative_path in expected:
        assert (PLUGIN_ROOT / relative_path).exists()


def test_no_orphan_top_level_scaffold_paths() -> None:
    allowed = {
        ".codex-plugin",
        ".github",
        ".gitignore",
        "README.md",
        "RELEASE_CHECKLIST.md",
        "assets",
        "docs",
        "hooks",
        "policies",
        "pyproject.toml",
        "skills",
        "src",
        "tests",
    }
    observed = {path.name for path in PLUGIN_ROOT.iterdir() if path.name not in GENERATED_NAMES}

    assert observed == allowed
