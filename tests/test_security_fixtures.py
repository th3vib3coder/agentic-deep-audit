from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import agentic_deep_audit.audit_inventory as audit_inventory
import agentic_deep_audit.audit_provenance as audit_provenance
from agentic_deep_audit.audit_evidence import evidence_for_records
from agentic_deep_audit.audit_provenance import run_git_command
from agentic_deep_audit.models import PLUGIN_ROOT


FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def test_security_fixture_git_config_poison_is_neutralized(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    git_dir = repo / ".git"
    git_dir.mkdir(parents=True)
    shutil.copyfile(FIXTURES / "security_git_config_poison" / "git_config", git_dir / "config")
    external = tmp_path / "bin"
    external.mkdir()
    fake_git = external / ("git.exe" if os.name == "nt" else "git")
    fake_git.write_text("", encoding="utf-8")
    observed: dict[str, object] = {}
    monkeypatch.setattr(audit_provenance.shutil, "which", lambda _tool: str(fake_git))

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(audit_provenance.subprocess, "run", fake_run)

    completed, _ = run_git_command(repo, ["status", "--porcelain"])

    command = observed["command"]
    assert completed.returncode == 0
    assert "core.fsmonitor=false" in command
    assert f"core.hooksPath={os.devnull}" in command
    assert "uploadpack.packObjectsHook=" in command
    assert "filter.lfs.required=false" in command
    assert "filter.lfs.clean=" in command
    assert "filter.lfs.smudge=" in command
    assert observed["env"]["GIT_CONFIG_GLOBAL"] == os.devnull


def test_security_fixture_symlink_escape_is_not_indexed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURES / "security_symlink_escape", repo)
    linked_outside = repo / "linked_outside"
    linked_outside.mkdir()
    secret = linked_outside / "secret.txt"
    secret.write_text("outside secret\n", encoding="utf-8")
    original_is_symlink = Path.is_symlink

    def fake_is_symlink(path: Path) -> bool:
        if path == linked_outside:
            return True
        return original_is_symlink(path)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)

    records, skipped, _ = audit_inventory.scan_files(
        {
            "repo": {"path": str(repo)},
            "scope_filters": {"include": ["**/*"], "exclude": []},
            "output_dir": "audit",
        }
    )

    indexed_hashes = {record["sha256"] for record in records}
    assert hashlib.sha256(secret.read_bytes()).hexdigest() not in indexed_hashes
    assert "linked_outside/secret.txt" not in {record["path"] for record in records}
    assert {item["path"]: item["reason"] for item in skipped}["linked_outside"] == "symlink skipped"


def test_security_fixture_path_traversal_records_are_rejected(tmp_path: Path) -> None:
    fixture = FIXTURES / "security_path_traversal_records"
    repo = tmp_path / "repo"
    repo.mkdir()
    shutil.copyfile(fixture / "safe.txt", repo / "safe.txt")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside secret\n", encoding="utf-8")
    records = json.loads((fixture / "records.json").read_text(encoding="utf-8"))

    payload = evidence_for_records(records, repo, {"repo": {}})

    assert [item["path"] for item in payload["evidence"]] == ["safe.txt"]
    assert payload["read_failures"] == [{"path": "../outside.txt", "reason": "PermissionError"}]
