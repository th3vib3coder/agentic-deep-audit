from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from agentic_deep_audit.config import ConfigError, resolve_repo_path
from agentic_deep_audit.limits import is_safe_repo_relative_path, resolve_repo_existing_file, resolve_repo_file
from agentic_deep_audit.models import PLUGIN_ROOT


PATH_POLICY_DOC = PLUGIN_ROOT / "docs" / "contracts" / "path_policy.md"


@pytest.mark.skipif(os.name != "nt", reason="drive-letter root paths are Windows-specific")
def test_windows_drive_path_accepted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved = resolve_repo_path(str(repo), None, [tmp_path])
    assert resolved == repo.resolve()
    assert re.match(r"^[A-Za-z]:", str(resolved)), f"Windows root should be a drive-letter path: {resolved}"


def test_unc_like_path_handled(tmp_path: Path) -> None:
    # A UNC-like path that does not exist must fail gracefully (ConfigError), never crash.
    with pytest.raises(ConfigError):
        resolve_repo_path(r"\\nonexistent-server\share\repo", None, [tmp_path])


@pytest.mark.skipif(os.name == "nt", reason="POSIX absolute root paths are POSIX-specific")
def test_posix_absolute_path_accepted(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    resolved = resolve_repo_path(str(repo), None, [tmp_path])
    assert resolved == repo.resolve()
    assert str(resolved).startswith("/"), f"POSIX root should be an absolute path: {resolved}"


def test_backslash_normalized(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    # Forward slashes are the normalized, accepted form for repo-relative paths.
    assert resolve_repo_file(repo, "src/app.py") == (repo / "src" / "app.py").resolve()
    # Backslash form is rejected (not silently accepted): callers must use the slash form.
    assert not is_safe_repo_relative_path("src\\app.py")
    assert resolve_repo_file(repo, "src\\app.py") is None


def test_colon_in_path_rejected_gracefully(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for value in ["a:b", "C:/Windows/win.ini", "stream:name"]:
        assert not is_safe_repo_relative_path(value)
        assert resolve_repo_file(repo, value) is None  # returns None, no crash


def test_dotdot_traversal_blocked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for value in ["../outside.txt", "a/../../b", "../../etc/passwd"]:
        assert not is_safe_repo_relative_path(value)
        assert resolve_repo_file(repo, value) is None


def test_symlink_resolved_where_available(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "real").mkdir(parents=True)
    target = repo / "real" / "file.py"
    target.write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n", encoding="utf-8")
    link = repo / "link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/privilege level")
    # A symlink that escapes the repo root resolves out of containment -> rejected.
    assert resolve_repo_file(repo, "link.py") is None
    # A normal in-repo file resolves fine.
    assert resolve_repo_file(repo, "real/file.py") == target.resolve()


@pytest.mark.skipif(os.name == "nt", reason="case-sensitivity is unverified on Windows (NTFS is case-insensitive by default)")
def test_case_sensitivity_noted_unverified_on_windows(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "App.py").write_text("x = 1\n", encoding="utf-8")
    # On a case-sensitive filesystem (POSIX), a differently-cased path is a distinct, missing file.
    assert resolve_repo_existing_file(repo, "App.py") is not None
    assert resolve_repo_existing_file(repo, "app.py") is None


def test_path_policy_doc_covers_matrix() -> None:
    lowered = PATH_POLICY_DOC.read_text(encoding="utf-8").lower()  # FileNotFoundError when absent (RED)
    for token in ("drive", "unc", "posix", "backslash", "colon", "..", "symlink", "case"):
        assert token in lowered, f"path_policy.md missing matrix token: {token!r}"
