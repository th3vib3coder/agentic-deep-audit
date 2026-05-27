from __future__ import annotations

import os
import stat
import sys
import shutil
import time
from pathlib import Path

import pytest


SRC = Path(__file__).resolve().parents[1] / "src"
PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SRC))
GENERATED_NAMES = {"build", "dist", ".coverage", ".pytest_cache", "__pycache__", "agentic_deep_audit.egg-info"}


def _retry_remove_readonly(function, path, _exc_info) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    time.sleep(0.05)
    function(path)


def remove_generated_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir() and not path.is_symlink():
        last_error: OSError | None = None
        for _attempt in range(5):
            try:
                shutil.rmtree(path, onerror=_retry_remove_readonly)
                return
            except OSError as exc:
                last_error = exc
                time.sleep(0.1)
        if last_error is not None:
            raise last_error
    else:
        try:
            path.unlink()
        except PermissionError:
            os.chmod(path, stat.S_IWRITE)
            path.unlink()


def cleanup_scaffold_artifacts() -> None:
    for target in [
        PLUGIN_ROOT / "build",
        PLUGIN_ROOT / "dist",
        PLUGIN_ROOT / "src" / "agentic_deep_audit.egg-info",
        PLUGIN_ROOT / ".coverage",
        PLUGIN_ROOT / ".pytest_cache",
    ]:
        remove_generated_path(target)
    for target in PLUGIN_ROOT.glob("*.egg-info"):
        remove_generated_path(target)


@pytest.fixture(autouse=True)
def clean_generated_scaffold_artifacts():
    cleanup_scaffold_artifacts()
    try:
        yield
    finally:
        cleanup_scaffold_artifacts()


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001 - pytest hook signature.
    cleanup_scaffold_artifacts()


def pytest_unconfigure(config):  # noqa: ARG001 - pytest hook signature.
    cleanup_scaffold_artifacts()
