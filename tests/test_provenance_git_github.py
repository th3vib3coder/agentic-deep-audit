from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_deep_audit.audit_provenance as audit_provenance
from agentic_deep_audit.audit_validate import validate_audit, validate_provenance_artifact
from agentic_deep_audit.audit_provenance import run_git_command
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
NO_GIT_FIXTURE = PLUGIN_ROOT / "tests" / "fixtures" / "no_git_repo"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def run_cli_with_env(*args: str, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )


def write_config(repo: Path, github: str | None = None, network_policy_file: str | None = None) -> Path:
    config = repo / "audit.config.yaml"
    lines = [
        'schema_version: "1.0"',
        "repo:",
        '  kind: "local"',
        '  path: "."',
        f'  github: "{github}"' if github else "  github: null",
        'profile: "minimal"',
        'mode: "source-audit"',
        'output_dir: "audit"',
        "scope_filters:",
        '  include: ["**/*"]',
        '  exclude: [".git/**", "node_modules/**"]',
        'target_context: "MIT downstream"',
        "binary_triage_consent: false",
    ]
    if network_policy_file:
        lines.append(f'network_policy_file: "{network_policy_file}"')
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def git_available() -> bool:
    return shutil.which("git") is not None


def run_git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, text=True, capture_output=True)


def prepare_git_repo(tmp_path: Path) -> Path:
    if not git_available():
        pytest.skip("git unavailable")
    repo = tmp_path / "git-repo"
    repo.mkdir()
    (repo / "README.md").write_text("# Git Repo\n", encoding="utf-8")
    write_config(repo)
    run_git(repo, "init")
    run_git(repo, "config", "user.email", "fixture@example.com")
    run_git(repo, "config", "user.name", "Fixture")
    run_git(repo, "add", "README.md", "audit.config.yaml")
    run_git(repo, "commit", "-m", "initial")
    run_git(repo, "tag", "v0.1.0")
    run_git(repo, "remote", "add", "origin", "https://ghp_ABCDEFGHIJKLMNOPQRST@github.com/example/project.git")
    (repo / ".gitmodules").write_text(
        '[submodule "lib"]\n\tpath = lib\n\turl = https://user:pass@example.com/lib.git\n',
        encoding="utf-8",
    )
    return repo


def test_no_git_repo_fixture_has_no_git_dir(tmp_path: Path) -> None:
    repo = tmp_path / "no-git"
    shutil.copytree(NO_GIT_FIXTURE, repo)
    write_config(repo)

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    provenance = json.loads((repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8"))
    assert provenance["git"]["status"] == "skipped"
    assert provenance["git"]["commit"] is None
    assert provenance["git"]["limitations"] == ["no git history available"]
    assert validate_audit(repo / "audit").ok


def test_git_provenance_uses_allowlisted_commands_and_redacts_remote(tmp_path: Path) -> None:
    repo = prepare_git_repo(tmp_path)

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    provenance_text = (repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8")
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in provenance_text
    assert "user:pass" not in provenance_text
    provenance = json.loads(provenance_text)
    git = provenance["git"]
    assert git["status"] == "observed"
    assert len(git["commit"]) == 40
    assert git["branch"] in {"master", "main"}
    assert "v0.1.0" in git["tags"]
    assert git["submodules"][0]["path"] == "lib"
    for command in git["commands"]:
        assert command["origin"] == "plugin_allowlist"
        assert command["decision"] == "allow"
        assert command["policy_rule"] == "plugin_allowlist"
        assert command["command"][1] in {"rev-parse", "status", "ls-files", "log"}


def test_github_metadata_status_skipped_without_network_and_no_secret_leak(tmp_path: Path) -> None:
    repo = prepare_git_repo(tmp_path)
    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr

    tool_status_text = (repo / "audit" / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8")
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in tool_status_text
    tool_status = json.loads(tool_status_text)
    github = [tool for tool in tool_status["tools"] if tool["tool"] == "github_metadata"][-1]
    assert github["status"] == "skipped"
    assert github["policy"] == "skipped"
    assert "network metadata disabled" in github["skipped_reason"]
    assert "mode=unauthenticated" in github["notes"]


def test_provenance_validator_rejects_empty_commit_without_limitation(tmp_path: Path) -> None:
    repo = prepare_git_repo(tmp_path)
    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)
    assert result.returncode == 0, result.stderr
    provenance_path = repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["git"]["commit"] = None
    provenance["git"]["limitations"] = []
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

    validation = validate_provenance_artifact(repo / "audit")

    assert not validation.ok
    assert any("commit SHA or explicit no-git limitation" in error for error in validation.errors)


def test_configured_github_token_is_redacted_from_all_artifacts(tmp_path: Path) -> None:
    repo = tmp_path / "configured-github"
    repo.mkdir()
    (repo / "README.md").write_text("# Configured\n", encoding="utf-8")
    token_url = "https://ghp_ABCDEFGHIJKLMNOPQRST@github.com/example/private.git"
    write_config(repo, github=token_url)

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    provenance_text = (repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8")
    tool_status_text = (repo / "audit" / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8")
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in provenance_text
    assert "ghp_ABCDEFGHIJKLMNOPQRST" not in tool_status_text
    provenance = json.loads(provenance_text)
    assert provenance["repo"]["github"] == "https://github.com/example/private.git"
    assert provenance["github"]["target"] == "example/private"
    assert validate_audit(repo / "audit").ok


def test_git_detected_from_subdirectory_repo_path(tmp_path: Path) -> None:
    repo = prepare_git_repo(tmp_path)
    package = repo / "pkg"
    package.mkdir()
    (package / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    write_config(package)

    result = run_cli("inventory", "--config", str(package / "audit.config.yaml"), cwd=package)

    assert result.returncode == 0, result.stderr
    provenance = json.loads((package / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8"))
    assert provenance["git"]["status"] == "observed"
    assert len(provenance["git"]["commit"]) == 40
    assert Path(provenance["git"]["repo_root"]).resolve() == repo.resolve()


def test_network_policy_deny_all_skips_github_metadata(tmp_path: Path) -> None:
    repo = prepare_git_repo(tmp_path)
    policy = repo / ".network_policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "default": "deny",
                "allowed_domains": [],
                "denied_domains": ["*"],
                "send_source_code": False,
                "rate_limits": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    write_config(repo, network_policy_file=".network_policy.json")

    result = run_cli("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo)

    assert result.returncode == 0, result.stderr
    tool_status = json.loads((repo / "audit" / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))
    github = [tool for tool in tool_status["tools"] if tool["tool"] == "github_metadata"][-1]
    assert github["status"] == "skipped"
    assert github["policy"] == "skipped"
    assert "network policy blocks GitHub metadata" in github["skipped_reason"]


def test_missing_git_executable_emits_provenance_fallback(tmp_path: Path) -> None:
    repo = tmp_path / "missing-git"
    repo.mkdir()
    (repo / "README.md").write_text("# Missing Git\n", encoding="utf-8")
    write_config(repo)
    env = cli_env()
    env["PATH"] = ""

    result = run_cli_with_env("inventory", "--config", str(repo / "audit.config.yaml"), cwd=repo, env=env)

    assert result.returncode == 0, result.stderr
    provenance = json.loads((repo / "audit" / ARTIFACT_PATHS["PROVENANCE"]).read_text(encoding="utf-8"))
    git = provenance["git"]
    assert git["status"] == "skipped"
    assert git["commit"] is None
    assert git["limitations"] == ["git executable not found"]
    assert git["commands"][0]["command"] == ["git", "rev-parse", "--show-toplevel"]
    assert git["commands"][0]["skipped_reason"] == "git executable not found"


def test_run_git_command_rejects_git_executable_inside_target(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_git = tmp_path / ("git.cmd" if os.name == "nt" else "git")
    fake_git.write_text("@echo poisoned\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(tmp_path))

    completed, record = run_git_command(tmp_path, ["rev-parse", "--show-toplevel"])

    assert completed.returncode == 127
    assert "inside target repo rejected" in record["skipped_reason"]


def test_run_git_command_rejects_git_executable_inside_parent_repo_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    subdir = repo / "pkg"
    subdir.mkdir(parents=True)
    (repo / ".git").mkdir()
    fake_git = repo / ("git.cmd" if os.name == "nt" else "git")
    fake_git.write_text("@echo poisoned\n", encoding="utf-8")
    monkeypatch.setenv("PATH", str(repo))

    completed, record = run_git_command(subdir, ["rev-parse", "--show-toplevel"])

    assert completed.returncode == 127
    assert "inside target repo rejected" in record["skipped_reason"]


def test_run_git_command_hardens_environment_and_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    external = tmp_path.parent / f"{tmp_path.name}-bin"
    external.mkdir()
    fake_git = external / ("git.exe" if os.name == "nt" else "git")
    fake_git.write_text("", encoding="utf-8")
    observed: dict[str, object] = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret-value")
    monkeypatch.setattr(audit_provenance.shutil, "which", lambda _tool: str(fake_git))

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = command
        observed["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(audit_provenance.subprocess, "run", fake_run)

    completed, record = run_git_command(tmp_path, ["status", "--porcelain"])

    command = observed["command"]
    env = observed["env"]
    assert completed.returncode == 0
    assert record["decision"] == "allow"
    assert "core.fsmonitor=false" in command
    assert f"core.hooksPath={os.devnull}" in command
    assert "uploadpack.packObjectsHook=" in command
    assert "protocol.ext.allow=never" in command
    assert "protocol.file.allow=never" in command
    assert "safe.directory=*" in command
    assert isinstance(env, dict)
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "ANTHROPIC_API_KEY" not in env
