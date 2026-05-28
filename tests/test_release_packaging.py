from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility.
    import tomli as tomllib

from agentic_deep_audit.models import PLUGIN_ROOT
from agentic_deep_audit.resources import policy_dir, schema_dir, template_dir


REPO_ROOT = Path(__file__).resolve().parents[1]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def clean_build_artifacts() -> None:
    for target in [PLUGIN_ROOT / "build", PLUGIN_ROOT / "dist", PLUGIN_ROOT / "src" / "agentic_deep_audit.egg-info"]:
        if target.exists():
            last_error: OSError | None = None
            for _attempt in range(5):
                try:
                    shutil.rmtree(target)
                    last_error = None
                    break
                except OSError as exc:
                    last_error = exc
                    time.sleep(0.1)
            if last_error is not None:
                raise last_error
    for target in PLUGIN_ROOT.glob("*.egg-info"):
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)


def build_wheel(tmp_path: Path) -> Path:
    clean_build_artifacts()
    wheel_dir = tmp_path / "wheels"
    result = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", str(PLUGIN_ROOT), "--no-deps", "--no-build-isolation", "-w", str(wheel_dir)],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        assert result.returncode == 0, result.stderr
        return next(wheel_dir.glob("agentic_deep_audit-*.whl"))
    finally:
        clean_build_artifacts()


def test_plugin_manifest_skill_route_and_permissions() -> None:
    manifest_path = PLUGIN_ROOT / ".codex-plugin" / "plugin.json"
    manifest = json.loads(read(manifest_path))
    claude_manifest = json.loads(read(PLUGIN_ROOT / ".claude-plugin" / "plugin.json"))

    assert manifest["name"] == "agentic-deep-audit"
    assert manifest["version"] == "0.1.0"
    assert manifest["permissions"]["network"] == "none"
    assert "Codex plugin" not in manifest["description"]
    assert manifest["skills"] == [{"name": "deep-repo-audit", "path": "skills/deep-repo-audit/SKILL.md"}]
    assert manifest["hooks"]["claude_code"] == "hooks/hooks.json"
    assert manifest["hooks"]["codex"] == "hooks/hooks.json"
    assert claude_manifest["hooks"]["settings"] == "hooks/hooks.json"
    for skill in manifest["skills"]:
        assert (PLUGIN_ROOT / skill["path"]).exists()
    assert (PLUGIN_ROOT / manifest["hooks"]["claude_code"]).exists()
    assert (PLUGIN_ROOT / claude_manifest["hooks"]["settings"]).exists()


def test_pre_tool_hook_is_registered_for_host_integration() -> None:
    hook_path = PLUGIN_ROOT / "hooks" / "hooks.json"
    hooks = json.loads(read(hook_path))

    pre_tool = hooks["hooks"]["PreToolUse"][0]
    registered = pre_tool["hooks"]
    assert "Bash" in pre_tool["matcher"]
    assert "mcp__" in pre_tool["matcher"]
    matcher = re.compile(pre_tool["matcher"])
    for tool_name in [
        "mcp__Desktop_Commander__start_process",
        "mcp__Desktop_Commander__execute_command",
        "mcp__Desktop_Commander__interact_with_process",
        "mcp__browser__click",
        "mcp__filesystem__write_file",
        "mcp__unknown__read_file",
    ]:
        assert matcher.fullmatch(tool_name)
    assert {hook["shell"] for hook in registered} == {"bash", "powershell"}
    assert all("AGENTIC_DEEP_AUDIT_PYTHON" in hook["command"] for hook in registered)
    assert all("--strict-runtime" in hook["command"] for hook in registered)
    assert all("hook_misconfigured" in hook["command"] for hook in registered)
    assert all("exit 2" in hook["command"] for hook in registered)
    assert all("platform" not in hook for hook in registered)
    assert all("args" not in hook for hook in registered)


def test_package_metadata_console_alias_and_plugin_name_align() -> None:
    pyproject = tomllib.loads(read(PLUGIN_ROOT / "pyproject.toml"))
    manifest = json.loads(read(PLUGIN_ROOT / ".codex-plugin" / "plugin.json"))

    assert pyproject["project"]["name"] == manifest["name"]
    assert pyproject["project"]["version"] == manifest["version"]
    assert pyproject["project"]["scripts"]["deep-audit"] == "agentic_deep_audit.cli:main"
    assert pyproject["project"]["requires-python"] >= ">=3.10"
    assert "Codex plugin" not in pyproject["project"]["description"]
    assert "audit engine" in pyproject["project"]["description"]
    assert "agentic_deep_audit" in pyproject["tool"]["setuptools"]["package-data"]
    package_data = pyproject["tool"]["setuptools"]["package-data"]["agentic_deep_audit"]
    assert "schemas/*.json" in package_data
    assert "policies/*.json" in package_data
    assert "templates/*" in package_data
    assert "docs/adapters/*/*.json" in package_data


def test_runtime_resources_are_available_from_package_namespace() -> None:
    assert (schema_dir() / "audit_config.schema.json").exists()
    assert (policy_dir() / "BLOCKED_COMMANDS_ALLOWLIST.json").exists()
    assert (template_dir() / "report.md").exists()


def test_built_wheel_contains_runtime_resources(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path)
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())

    for resource in [
        "agentic_deep_audit/schemas/audit_config.schema.json",
        "agentic_deep_audit/schemas/core_envelope.schema.json",
        "agentic_deep_audit/policies/BLOCKED_COMMANDS_ALLOWLIST.json",
        "agentic_deep_audit/policies/DEFAULT_NETWORK_POLICY.json",
        "agentic_deep_audit/templates/report.md",
        "agentic_deep_audit/docs/adapters/graphify/adapter_decision.json",
    ]:
        assert resource in names


def test_installed_wheel_loads_runtime_resources_and_adapter_decision(tmp_path: Path) -> None:
    wheel = build_wheel(tmp_path)
    fake_checkout = tmp_path / "fake-checkout"
    (fake_checkout / "src" / "agentic_deep_audit").mkdir(parents=True)
    (fake_checkout / "pyproject.toml").write_text("[project]\nname = 'fake'\n", encoding="utf-8")
    venv = fake_checkout / ".venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    install = subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)], text=True, capture_output=True, check=False)
    assert install.returncode == 0, install.stderr
    probe = subprocess.run(
        [
            str(python),
            "-c",
            "\n".join(
                [
                    "from pathlib import Path",
                    "import agentic_deep_audit",
                    "from agentic_deep_audit.models import PLUGIN_ROOT, SCHEMA_FILES, load_schema_registry",
                    "from agentic_deep_audit.resources import policy_dir, template_dir",
                    "from agentic_deep_audit.adapters.loader import validate_adapter_promotion, AdapterBlockedPrePromotion",
                    "package_root = Path(agentic_deep_audit.__file__).resolve().parent",
                    "assert Path(PLUGIN_ROOT).resolve() == package_root, f'{PLUGIN_ROOT} != {package_root}'",
                    "assert len(load_schema_registry()) == len(SCHEMA_FILES)",
                    "assert (policy_dir() / 'BLOCKED_COMMANDS_ALLOWLIST.json').exists()",
                    "assert (template_dir() / 'report.md').exists()",
                    "try:",
                    "    validate_adapter_promotion(PLUGIN_ROOT, 'graphify', 'industry-known')",
                    "    raise SystemExit('expected graphify defer')",
                    "except AdapterBlockedPrePromotion as exc:",
                    "    assert 'decision is defer' in str(exc), str(exc)",
                ]
            ),
        ],
        cwd=fake_checkout,
        text=True,
        capture_output=True,
        check=False,
    )
    assert probe.returncode == 0, probe.stderr


def test_release_docs_cover_profiles_windows_adapters_and_caveats() -> None:
    readme = read(PLUGIN_ROOT / "README.md")
    profiles = read(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "references" / "profiles.md")
    adapters = read(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "references" / "tool_adapters.md")

    for profile in ["Minimal Offline", "Standard Local", "Extended With MCP/Cloud", "Research/Binary"]:
        assert profile in readme
        assert profile in profiles
    for token in ["Windows", "TOOL_STATUS.json", "skipped", "deferred", "Graphify", "Adapter Promotion", "ADAPTER_EVALUATION.md"]:
        assert token in readme
    assert "Codex v1 plugin" not in readme
    assert '$env:PYTHONPATH = "src"' in readme
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
        "362 collected tests",
        "test_release_packaging.py",
        "run_smoke_tests.py",
        "test_pre_tool_policy.py",
        "test_wiki_pages.py",
        "check_gate_paths.py",
        "check_seq_atomicity.py",
        "check_plan_traceability.py",
        "compileall",
        "git diff --check",
    ]:
        assert command in checklist
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        if len(cells) >= 3:
            assert cells[2]
    assert "Codex plugin package" not in checklist
    assert "audit engine package" in checklist


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
