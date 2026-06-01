from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
GENERATED_NAMES = {".git", ".pytest_cache", ".ruff_cache", "__pycache__", "build", "dist", ".coverage"}


def test_plugin_manifest_contract() -> None:
    manifest = json.loads((PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8"))

    assert manifest["name"] == "agentic-deep-audit"
    assert manifest["version"] == "0.1.0"
    assert manifest["skills"][0]["path"] == "skills/deep-repo-audit/SKILL.md"
    assert manifest["permissions"]["network"] == "none"


def test_python_package_scaffold() -> None:
    init_file = PLUGIN_ROOT / "src" / "agentic_deep_audit" / "__init__.py"

    assert init_file.exists()
    # S-B05: the package __init__ re-exports the frozen public API surface (was empty pre-S-B05).
    init_contents = init_file.read_text(encoding="utf-8")
    assert "from .bootstrap import bootstrap_audit" in init_contents
    assert "from .audit_validate import validate_audit" in init_contents
    assert '__all__ = ["bootstrap_audit", "validate_audit"]' in init_contents


def test_pyproject_metadata_contract() -> None:
    pyproject_text = (PLUGIN_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyproject = tomllib.loads(pyproject_text)

    assert pyproject["project"]["name"] == "agentic-deep-audit"
    assert pyproject["project"]["requires-python"] == ">=3.10"
    assert "jsonschema>=4.0" in pyproject["project"]["dependencies"]
    assert "PyYAML>=6.0" in pyproject["project"]["dependencies"]
    assert pyproject["project"]["scripts"]["deep-audit"] == "agentic_deep_audit.cli:main"


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
        ".claude-plugin",
        ".codex-plugin",
        ".gitattributes",
        ".github",
        ".gitignore",
        "README.md",
        "RELEASE_CHECKLIST.md",
        "assets",
        "commands",
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
