from __future__ import annotations

import subprocess
from pathlib import Path

from agentic_deep_audit import gate


def test_changed_paths_uses_hardened_git_invocations(monkeypatch, tmp_path: Path) -> None:
    observed: list[dict[str, object]] = []
    monkeypatch.setattr(gate, "safe_git_executable", lambda _repo: ("git-safe", None))
    monkeypatch.setattr(gate, "git_probe_env", lambda: {"GIT_CONFIG_NOSYSTEM": "1"})

    def fake_run(command, **kwargs):
        observed.append({"command": command, "env": kwargs.get("env")})
        stdout = "src/example.py\n" if "diff" in command else "untracked.txt\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)

    assert gate.changed_paths(tmp_path, "HEAD") == ["src/example.py", "untracked.txt"]

    assert len(observed) == 2
    for call in observed:
        command = call["command"]
        assert isinstance(command, list)
        assert command[0] == "git-safe"
        assert "protocol.ext.allow=never" in command
        assert "protocol.file.allow=never" in command
        assert call["env"] == {"GIT_CONFIG_NOSYSTEM": "1"}
