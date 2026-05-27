"""Package resource lookup with source-tree fallback."""

from __future__ import annotations

from importlib import resources
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent


def source_plugin_root() -> Path:
    """Return the checkout plugin root when present, else the installed package root."""

    source_root = PACKAGE_ROOT.parent.parent
    expected_package = source_root / "src" / "agentic_deep_audit"
    if PACKAGE_ROOT.parent.name == "src" and (source_root / "pyproject.toml").exists():
        try:
            if expected_package.resolve() == PACKAGE_ROOT:
                return source_root
        except OSError:
            pass
    return PACKAGE_ROOT


SOURCE_PLUGIN_ROOT = source_plugin_root()


def package_resource_dir(name: str, source_fallback: Path) -> Path:
    """Return a package data directory when installed, or the source tree path."""

    try:
        resource = resources.files("agentic_deep_audit").joinpath(name)
        candidate = Path(str(resource))
        if resource.is_dir() and candidate.exists():
            return candidate
    except (ModuleNotFoundError, TypeError, ValueError):
        pass
    return source_fallback


def schema_dir() -> Path:
    return package_resource_dir(
        "schemas",
        SOURCE_PLUGIN_ROOT / "skills" / "deep-repo-audit" / "schemas",
    )


def policy_dir() -> Path:
    return package_resource_dir("policies", SOURCE_PLUGIN_ROOT / "policies")


def template_dir() -> Path:
    return package_resource_dir("templates", SOURCE_PLUGIN_ROOT / "assets" / "templates")
