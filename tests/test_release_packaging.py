from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from agentic_deep_audit.models import PLUGIN_ROOT



def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_plugin_manifest_skill_route_and_permissions() -> None:
    manifest_path = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
    manifest = json.loads(read(manifest_path))

    assert manifest["name"] == "agentic-deep-audit"
    assert manifest["version"] == "0.1.0"
    assert manifest["permissions"]["network"] == "none"
    assert manifest["skills"] == [{"name": "deep-repo-audit", "path": "skills/deep-repo-audit/SKILL.md"}]
    for skill in manifest["skills"]:
        assert (PLUGIN_ROOT / skill["path"]).exists()


def test_package_metadata_console_alias_and_plugin_name_align() -> None:
    pyproject = tomllib.loads(read(PLUGIN_ROOT / "pyproject.toml"))
    manifest = json.loads(read(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"))

    assert pyproject["project"]["name"] == manifest["name"]
    assert pyproject["project"]["version"] == manifest["version"]
    assert pyproject["project"]["scripts"]["deep-audit"] == "agentic_deep_audit.cli:main"
    assert pyproject["project"]["requires-python"] >= ">=3.10"


def test_release_docs_cover_profiles_windows_adapters_and_caveats() -> None:
    readme = read(PLUGIN_ROOT / "README.md")
    profiles = read(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "references" / "profiles.md")
    adapters = read(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "references" / "tool_adapters.md")

    for profile in ["Minimal Offline", "Standard Local", "Extended With MCP/Cloud", "Research/Binary"]:
        assert profile in readme
        assert profile in profiles
    for token in ["Windows", "TOOL_STATUS.json", "skipped", "deferred", "Graphify", "Adapter Promotion", "ADAPTER_EVALUATION.md"]:
        assert token in readme
    for token in ["SBOM", "SAST", "SQLite+FTS5", "GitHub metadata", "issue/PR/release/CI", "CVE", "scorecards", "advanced graph/code intelligence"]:
        assert token in readme
        assert token in profiles
    for caveat in ["legal advice", "absence of vulnerabilities", "production safety", "untrusted repository code"]:
        assert caveat in readme
    assert "Source-claim tools are not accepted dependencies" in readme
    assert "Source-claim tools must not be described as accepted runtime dependencies" in adapters


def test_release_checklist_commands_have_expected_conditions() -> None:
    checklist = read(PLUGIN_ROOT / "RELEASE_CHECKLIST.md")
    rows = [line for line in checklist.splitlines() if line.startswith("| ") and "`" in line and "Expected pass condition" not in line]

    assert rows
    for command in [
        "pytest tests -q",
        "255 collected tests",
        "test_release_packaging.py",
        "run_smoke_tests.py",
        "test_pre_tool_policy.py",
        "test_wiki_pages.py",
        "compileall",
        "git diff --check",
    ]:
        assert command in checklist
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if len(cells) >= 3:
            assert cells[2]


def test_release_docs_do_not_overclaim_optional_adapters() -> None:
    readme = read(PLUGIN_ROOT / "README.md")
    forbidden = [
        r"Graphify is accepted",
        r"source-claim tools are accepted",
        r"\bcertifies absence of vulnerabilities",
        r"guarantees production safety",
    ]

    for pattern in forbidden:
        assert not re.search(pattern, readme, flags=re.IGNORECASE)
