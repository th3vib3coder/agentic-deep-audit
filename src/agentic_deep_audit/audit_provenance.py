"""Phase 1 git and GitHub provenance collection."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from .audit_evidence import sync_evidence_identity_from_provenance
from .bootstrap import enrich_tool_status
from .limits import FileSizeLimitError, read_text_auto_capped
from .mcp_policy import looks_secret, redact_value
from .models import ARTIFACT_PATHS
from .policy import decide_command, decide_network


GIT_SAFE_CONFIG = [
    "-c",
    "core.fsmonitor=false",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "uploadpack.packObjectsHook=",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "protocol.file.allow=never",
    "-c",
    "safe.directory=*",
    "-c",
    "diff.external=",
    "-c",
    "filter.lfs.required=false",
    "-c",
    "filter.lfs.clean=",
    "-c",
    "filter.lfs.smudge=",
]


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def local_git_roots(repo_path: Path) -> list[Path]:
    roots = [repo_path.resolve()]
    current = repo_path.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            roots.append(candidate.resolve())
            break
    return list(dict.fromkeys(roots))


def safe_git_executable(repo_path: Path) -> tuple[str | None, str | None]:
    command_path = shutil.which("git")
    if command_path is None:
        return None, "git executable not found"
    resolved = Path(command_path).resolve()
    for root in local_git_roots(repo_path):
        if _inside(resolved, root):
            return None, f"git executable inside target repo rejected: {resolved}"
    return str(resolved), None


def git_probe_env() -> dict[str, str]:
    keep = {"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TMP", "TEMP"}
    env = {key: value for key, value in os.environ.items() if key.upper() in keep}
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_EXTERNAL_DIFF": "",
            "HOME": "",
        }
    )
    return env


def run_git_command(repo_path: Path, args: list[str]) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    command = ["git", *args]
    decision = decide_command(command, origin="plugin_allowlist")
    record = {
        "command": command,
        "origin": decision.origin,
        "decision": decision.decision,
        "policy_rule": decision.policy_rule,
        "exit_code": None,
    }
    if not decision.allowed:
        raise RuntimeError(f"git command blocked by policy: {decision.reason}")
    git_path, skipped_reason = safe_git_executable(repo_path)
    if skipped_reason is not None or git_path is None:
        completed = subprocess.CompletedProcess(command, 127, "", skipped_reason or "git executable unavailable")
        record["exit_code"] = completed.returncode
        record["skipped_reason"] = skipped_reason or "git executable unavailable"
        return completed, record
    try:
        completed = subprocess.run(
            [git_path, *GIT_SAFE_CONFIG, *args],
            cwd=repo_path,
            env=git_probe_env(),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        completed = subprocess.CompletedProcess(command, 124, "", "git command timed out")
    except OSError as exc:
        completed = subprocess.CompletedProcess(command, 127, "", f"git command failed to start: {exc}")
    record["exit_code"] = completed.returncode
    if completed.returncode == 127:
        record["skipped_reason"] = completed.stderr or "git executable not found"
    if completed.returncode == 124:
        record["skipped_reason"] = "git command timed out"
    return completed, record


def parse_git_config_remotes(git_dir: Path) -> list[dict[str, str | None]]:
    config = git_dir / "config"
    if not config.exists():
        return []
    remotes: list[dict[str, str | None]] = []
    current: dict[str, str | None] | None = None
    try:
        config_text = read_text_auto_capped(config, encoding="utf-8", errors="replace", label="git config")
    except (OSError, FileSizeLimitError):
        return []
    for line in config_text.splitlines():
        stripped = line.strip()
        match = re.fullmatch(r'\[remote "([^"]+)"\]', stripped)
        if match:
            current = {"name": match.group(1), "url": None}
            remotes.append(current)
            continue
        if current is not None and stripped.startswith("url") and "=" in stripped:
            current["url"] = redact_remote_url(stripped.split("=", 1)[1].strip())
    return remotes


def redact_remote_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunparse((parsed.scheme, host, parsed.path, "", "", ""))
    return str(redact_value(value))


MAX_PROVENANCE_SANITIZE_DEPTH = 256


def sanitize_for_provenance(value: Any, depth: int = 0) -> Any:
    if depth > MAX_PROVENANCE_SANITIZE_DEPTH:
        return "<redacted:depth-limit>"
    if isinstance(value, dict):
        return {key: sanitize_for_provenance(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_for_provenance(item, depth + 1) for item in value]
    if isinstance(value, str):
        parsed = urlparse(value)
        if parsed.username or parsed.password:
            return redact_remote_url(value)
        return redact_value(value)
    return value


def github_target_from_url(value: str) -> tuple[str | None, str | None]:
    sanitized = redact_remote_url(value)
    parsed = urlparse(sanitized if "://" in sanitized else "")
    if "github.com:" in sanitized:
        path = sanitized.split("github.com:", 1)[1]
        mode = "ssh"
    elif parsed.hostname == "github.com":
        path = parsed.path.lstrip("/")
        mode = "unauthenticated"
    else:
        return None, None
    path = path.removesuffix(".git")
    if path.count("/") >= 1:
        owner, repo_name = path.split("/", 1)
        return f"{owner}/{repo_name}", mode
    return None, None


def parse_tags(git_dir: Path) -> list[str]:
    tags: set[str] = set()
    tag_root = git_dir / "refs" / "tags"
    if tag_root.exists():
        for path in tag_root.rglob("*"):
            if path.is_file():
                tags.add(path.relative_to(tag_root).as_posix())
    packed = git_dir / "packed-refs"
    if packed.exists():
        try:
            packed_text = read_text_auto_capped(packed, encoding="utf-8", errors="replace", label="packed refs")
        except (OSError, FileSizeLimitError):
            packed_text = ""
        for line in packed_text.splitlines():
            if line.startswith("#") or not line.strip() or line.startswith("^"):
                continue
            parts = line.split()
            if len(parts) == 2 and parts[1].startswith("refs/tags/"):
                tags.add(parts[1].removeprefix("refs/tags/"))
    return sorted(tags)


def parse_submodules(repo_path: Path) -> list[dict[str, str | None]]:
    gitmodules = repo_path / ".gitmodules"
    if not gitmodules.exists():
        return []
    submodules: list[dict[str, str | None]] = []
    current: dict[str, str | None] | None = None
    try:
        gitmodules_text = read_text_auto_capped(gitmodules, encoding="utf-8", errors="replace", label="gitmodules")
    except (OSError, FileSizeLimitError):
        return []
    for line in gitmodules_text.splitlines():
        stripped = line.strip()
        match = re.fullmatch(r'\[submodule "([^"]+)"\]', stripped)
        if match:
            current = {"name": match.group(1), "path": None, "url": None}
            submodules.append(current)
            continue
        if current is not None and "=" in stripped:
            key, value = [part.strip() for part in stripped.split("=", 1)]
            if key in {"path", "url"}:
                current[key] = str(redact_value(value)) if key == "url" else value
    return submodules


def resolve_github_target(run_config: dict[str, Any], remotes: list[dict[str, str | None]]) -> tuple[str | None, str]:
    repo = run_config.get("repo") or {}
    configured = repo.get("github") if isinstance(repo, dict) else None
    if isinstance(configured, str) and configured:
        target, _ = github_target_from_url(configured)
        return target or str(sanitize_for_provenance(configured)), "configured"
    if isinstance(configured, dict) and configured.get("owner") and configured.get("repo"):
        return f"{configured['owner']}/{configured['repo']}", "configured"
    for remote in remotes:
        url = remote.get("url") or ""
        target, mode = github_target_from_url(url)
        if target and mode:
            return target, mode
    return None, "manual-local"


def append_github_tool_status(audit_dir: Path, run_config: dict[str, Any], github_target: str | None, mode: str) -> None:
    path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    payload = json.loads(read_text_auto_capped(path, encoding="utf-8", label="tool status")) if path.exists() else {"schema_version": "1.0", "tools": []}
    network_snapshot = audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]
    github_network_allowed = False
    if network_snapshot.exists():
        policy = json.loads(read_text_auto_capped(network_snapshot, encoding="utf-8", label="network policy snapshot"))
        github_network_allowed = decide_network("api.github.com", policy=policy).allowed
    if github_network_allowed and github_target:
        record = {
            "tool": "github_metadata",
            "status": "deferred",
            "available": False,
            "version": None,
            "command": [],
            "phase": "1",
            "policy": "deferred",
            "exit_code": None,
            "skipped_reason": "GitHub metadata adapter deferred to later network/MCP phase",
            "os": "all",
            "capability": "github_metadata",
            "degradation": f"mode={mode}; target={github_target}",
            "notes": [],
        }
        record = enrich_tool_status(record, capability="github_metadata", provenance_class="source-claim")
    else:
        reason = "network metadata disabled or GitHub target unavailable"
        if network_snapshot.exists() and not github_network_allowed:
            reason = "network policy blocks GitHub metadata"
        record = {
            "tool": "github_metadata",
            "status": "skipped",
            "available": False,
            "version": None,
            "command": [],
            "phase": "1",
            "policy": "skipped",
            "exit_code": None,
            "skipped_reason": reason,
            "notes": [f"mode={mode}", f"target={github_target or 'none'}"],
        }
        record = enrich_tool_status(record, capability="github_metadata", provenance_class="source-claim")
    payload.setdefault("tools", []).append(record)
    write_json(path, payload)


def collect_git_metadata(repo_path: Path) -> dict[str, Any]:
    root_probe, root_record = run_git_command(repo_path, ["rev-parse", "--show-toplevel"])
    if root_probe.returncode != 0:
        limitation = "git executable not found" if root_probe.returncode == 127 else "no git history available"
        return {
            "status": "skipped",
            "target_path": str(repo_path),
            "repo_root": str(repo_path),
            "commit": None,
            "branch": None,
            "dirty": None,
            "tracked_file_count": 0,
            "remotes": [],
            "tags": [],
            "submodules": [],
            "commands": [root_record],
            "limitations": [limitation],
        }
    repo_root = Path(root_probe.stdout.strip()).resolve()
    git_dir = repo_root / ".git"
    commands: list[dict[str, Any]] = []
    commands.append(root_record)
    command_results: dict[str, subprocess.CompletedProcess[str]] = {}
    command_results["root"] = root_probe
    for key, args in {
        "commit": ["rev-parse", "HEAD"],
        "branch": ["rev-parse", "--abbrev-ref", "HEAD"],
        "status": ["status", "--porcelain"],
        "ls_files": ["ls-files"],
        "log_head": ["log", "-1", "--format=%H"],
    }.items():
        completed, record = run_git_command(repo_path, args)
        commands.append(record)
        command_results[key] = completed
    commit = command_results["commit"].stdout.strip() if command_results["commit"].returncode == 0 else None
    branch = command_results["branch"].stdout.strip() if command_results["branch"].returncode == 0 else None
    tracked = [line for line in command_results["ls_files"].stdout.splitlines() if line.strip()] if command_results["ls_files"].returncode == 0 else []
    limitations = []
    if not commit:
        limitations.append("git commit unavailable")
    return {
        "status": "observed" if commit else "failed",
        "target_path": str(repo_path),
        "repo_root": str(repo_root),
        "commit": commit,
        "branch": branch,
        "dirty": bool(command_results["status"].stdout.strip()) if command_results["status"].returncode == 0 else None,
        "tracked_file_count": len(tracked),
        "remotes": parse_git_config_remotes(git_dir),
        "tags": parse_tags(git_dir),
        "submodules": parse_submodules(repo_root),
        "commands": commands,
        "limitations": limitations,
    }


def run_provenance(run_config: dict[str, Any], audit_dir: Path) -> None:
    repo_path = Path(str((run_config.get("repo") or {}).get("path") or ".")).resolve()
    git = collect_git_metadata(repo_path)
    github_target, github_mode = resolve_github_target(run_config, git.get("remotes", []))
    github = {"target": github_target, "auth_mode": github_mode, "metadata_status": "skipped_or_deferred"}
    repo_payload = sanitize_for_provenance(run_config.get("repo") or {"path": str(repo_path), "commit": git.get("commit")})
    provenance = {
        "schema_version": "1.0",
        "run_id": run_config.get("run_id"),
        "repo": repo_payload,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_artifacts": [ARTIFACT_PATHS["RUN_CONFIG"], ARTIFACT_PATHS["FILE_INDEX"]],
        "records": [{"kind": "git", **git}, {"kind": "github", **github}],
        "skipped": False,
        "skip_reason": None,
        "git": git,
        "github": github,
    }
    write_json(audit_dir / ARTIFACT_PATHS["PROVENANCE"], provenance)
    sync_evidence_identity_from_provenance(audit_dir, provenance)
    append_github_tool_status(audit_dir, run_config, github_target, github_mode)
