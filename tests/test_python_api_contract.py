"""Contract tests for the Python API adapter (S-B05).

The public API surface is frozen and enumerated here as the SINGLE SOURCE OF TRUTH; adding a name
later requires a ledger amendment (005 convention 7). docs/adapters/python-api.md documents exactly
these names, and src/agentic_deep_audit/__init__.py re-exports exactly these via __all__.
"""

from __future__ import annotations

import importlib
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PYTHON_API_DOC = PACKAGE_ROOT / "docs" / "adapters" / "python-api.md"

# Frozen public API surface.
PUBLIC_API = ("bootstrap_audit", "validate_audit")


def test_public_api_functions_importable() -> None:
    module = importlib.import_module("agentic_deep_audit")
    for name in PUBLIC_API:
        assert hasattr(module, name), f"agentic_deep_audit must re-export {name}"
        assert callable(getattr(module, name)), f"{name} must be callable"
    # __all__ must equal the frozen surface exactly (no drift in either direction).
    assert set(getattr(module, "__all__", [])) == set(PUBLIC_API)


def test_public_api_dry_run_or_minimal_validate(tmp_path: Path) -> None:
    from agentic_deep_audit import validate_audit

    # Minimal validate on an empty directory: a documented entry point that executes and returns
    # a ValidationResult without raising (proves the surface is callable, not only importable).
    result = validate_audit(tmp_path)
    assert result is not None
    assert hasattr(result, "ok")


def test_python_api_doc_declares_promotion_contract() -> None:
    text = PYTHON_API_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    assert "documented-beta" in lowered
    assert "semver" in lowered or "semantic versioning" in lowered
    assert "import-path stability" in lowered or "import path stability" in lowered
    assert "deprecation" in lowered
    # promotion trigger per 006 Python API Promotion Gate
    assert "three stable releases" in lowered or "external review" in lowered
