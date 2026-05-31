from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from agentic_deep_audit.models import PLUGIN_ROOT


SRC = PLUGIN_ROOT / "src" / "agentic_deep_audit"
# gate.py lists ".codex-plugin/**" in PROJECT_SURFACE_PATTERNS — a symmetric path policy
# (alongside .claude-plugin and other project dirs), pure data, not an import-time manifest read.
CODEX_PLUGIN_REFERENCE_ALLOWLIST = {"gate.py"}


def _export_without_codex_plugin(tmp_path: Path) -> Path:
    """Build a minimal source export (src/ + pyproject.toml) with NO .codex-plugin/."""
    export = tmp_path / "export"
    shutil.copytree(SRC, export / "src" / "agentic_deep_audit", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(PLUGIN_ROOT / "pyproject.toml", export / "pyproject.toml")
    assert not (export / ".codex-plugin").exists(), "export must not contain .codex-plugin/"
    return export


def _run_in_export(export: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(export / "src")  # prepended ahead of any editable install
    return subprocess.run([sys.executable, *args], cwd=export, env=env, capture_output=True, text=True)


def test_no_module_imports_codex_plugin_json_unconditionally() -> None:
    offenders = [
        path.name
        for path in SRC.rglob("*.py")
        if ".codex-plugin" in path.read_text(encoding="utf-8") and path.name not in CODEX_PLUGIN_REFERENCE_ALLOWLIST
    ]
    assert not offenders, f"modules reference .codex-plugin outside the allowlist (would couple non-Codex startup): {offenders}"


def test_cli_help_passes_without_codex_plugin(tmp_path: Path) -> None:
    export = _export_without_codex_plugin(tmp_path)
    result = _run_in_export(export, "-m", "agentic_deep_audit.cli", "--help")
    assert result.returncode == 0, result.stderr
    assert "usage" in result.stdout.lower()


def test_python_api_import_passes_without_codex_plugin(tmp_path: Path) -> None:
    export = _export_without_codex_plugin(tmp_path)
    result = _run_in_export(
        export,
        "-c",
        "import agentic_deep_audit, pathlib; "
        "from agentic_deep_audit import validate_audit, bootstrap_audit; "
        "print(pathlib.Path(agentic_deep_audit.__file__).resolve())",
    )
    assert result.returncode == 0, result.stderr
    # Hermetic check: the export (PYTHONPATH) must win over any editable install, which could
    # otherwise shadow this with a tree that HAS .codex-plugin and falsely pass.
    resolved_pkg = Path(result.stdout.strip()).resolve().parent
    assert resolved_pkg == (export / "src" / "agentic_deep_audit").resolve(), (
        f"API import resolved outside the no-codex export (non-hermetic): {resolved_pkg}"
    )


def test_installed_wheel_smoke_passes_without_codex_plugin(tmp_path: Path) -> None:
    from test_release_packaging import build_wheel

    wheel = build_wheel(tmp_path)
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    bindir = "Scripts" if os.name == "nt" else "bin"
    python = venv / bindir / ("python.exe" if os.name == "nt" else "python")
    install = subprocess.run([str(python), "-m", "pip", "install", str(wheel)], capture_output=True, text=True)
    assert install.returncode == 0, install.stderr

    # The wheel does not package .codex-plugin/ (not in [tool.setuptools.package-data]); the
    # installed package root must therefore lack it, and deep-audit --help must still work.
    site = subprocess.run(
        [str(python), "-c", "import agentic_deep_audit, pathlib; print(pathlib.Path(agentic_deep_audit.__file__).resolve().parent)"],
        capture_output=True,
        text=True,
    )
    assert site.returncode == 0, site.stderr
    assert not (Path(site.stdout.strip()) / ".codex-plugin").exists(), "installed wheel must not ship .codex-plugin/"

    deep_audit = venv / bindir / ("deep-audit.exe" if os.name == "nt" else "deep-audit")
    result = subprocess.run([str(deep_audit), "--help"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "usage" in result.stdout.lower()
