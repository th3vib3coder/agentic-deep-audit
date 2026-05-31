"""Phase 0 bootstrap for Agentic Deep Audit runs."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

from .artifact_io import write_json_artifact
from .config import ArgvOverrides, ConfigError, build_launch_surface, load_config_file, load_run_config, normalize_run_config, sha256_file
from .limits import FileSizeLimitError, read_bytes_capped
from .models import ARTIFACT_PATHS


PHASES: list[tuple[int, str]] = [
    (0, "Bootstrap Sicuro"),
    (1, "Inventory E Provenance"),
    (2, "Manifest, Build, Test, CI"),
    (3, "Code Graph E Module Graph"),
    (4, "Superfici Pubbliche"),
    (5, "Feature, Pattern E Candidati Riuso"),
    (6, "Risk, Supply-Chain, Licenze"),
    (7, "Performance, Qualita' E Riuso"),
    (8, "Wiki, Graph E Corpus"),
    (9, "Review, Validation E Report Finale"),
]


class BootstrapError(ConfigError):
    """Raised when phase 0 cannot create a reproducible run state."""


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


def enrich_tool_status(record: dict[str, Any], capability: str, provenance_class: str = "core") -> dict[str, Any]:
    status = record.get("status")
    available = bool(record.get("available"))
    record.setdefault("os", platform.system() or "unknown")
    record.setdefault("capability", capability)
    record.setdefault("availability", "available" if available else "missing")
    record.setdefault("provenance_class", provenance_class)
    if status in {"skipped", "blocked", "failed", "degraded", "deferred"}:
        reason = record.get("skipped_reason") or record.get("degradation") or f"{record.get('tool')} unavailable"
        record.setdefault("degradation_reason", reason)
        record.setdefault("degradation", reason)
    return record


def resolve_output_dir(output_dir: str, cwd: Path) -> Path:
    configured = Path(output_dir)
    resolved = (configured if configured.is_absolute() else cwd / configured).resolve()
    allowed_root = cwd.resolve()
    try:
        resolved.relative_to(allowed_root)
    except ValueError as exc:
        raise BootstrapError(f"output dir outside allowed root: {resolved}") from exc
    return resolved


def write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_artifact(path, payload)


def copy_snapshot(source: Path, destination: Path) -> str:
    try:
        data = read_bytes_capped(source, label="bootstrap snapshot")
    except (FileSizeLimitError, OSError) as exc:
        raise BootstrapError(f"snapshot read failed: {source}: {exc}") from exc
    destination.write_bytes(data)
    return sha256_file(destination)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def local_execution_roots(root: Path) -> list[Path]:
    roots = [root.resolve()]
    current = root.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / ".git").exists():
            roots.append(candidate.resolve())
            break
    return list(dict.fromkeys(roots))


def subprocess_probe_env() -> dict[str, str]:
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


def git_probe_env() -> dict[str, str]:
    return subprocess_probe_env()


def skipped_tool_status(tool: str, version_args: list[str], reason: str, notes: list[str] | None = None, exit_code: int | None = None) -> dict[str, Any]:
    return enrich_tool_status(
        {
        "tool": tool,
        "status": "skipped",
        "available": False,
        "version": None,
        "command": [tool, *version_args],
        "phase": "0",
        "policy": "skipped",
        "exit_code": exit_code,
        "skipped_reason": reason,
        "notes": notes or [],
        },
        capability=f"{tool}_version_probe",
        provenance_class="core-optional",
    )


def detect_command(tool: str, version_args: list[str], allowed_root: Path | None = None) -> dict[str, Any]:
    command_path = shutil.which(tool)
    if command_path is None:
        return skipped_tool_status(tool, version_args, f"{tool} not found on PATH")
    resolved_command = Path(command_path).resolve()
    root = (allowed_root or Path.cwd()).resolve()
    forbidden_roots = local_execution_roots(root) if tool == "git" else [root]
    matched_root = next((candidate for candidate in forbidden_roots if _inside(resolved_command, candidate)), None)
    if matched_root is not None:
        return skipped_tool_status(
            tool,
            version_args,
            f"{tool} path inside audit target root rejected",
            notes=[str(resolved_command), f"target_root={matched_root}"],
        )
    command = [str(resolved_command), *version_args]
    env = subprocess_probe_env()
    if tool == "git":
        command = [str(resolved_command), *GIT_SAFE_CONFIG, *version_args]
        env = git_probe_env()
    try:
        completed = subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=10,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return skipped_tool_status(tool, version_args, f"{tool} version command timed out", notes=[str(resolved_command)])
    except OSError as exc:
        return skipped_tool_status(tool, version_args, f"{tool} version command failed to start: {exc}", notes=[str(resolved_command)])
    version = (completed.stdout or completed.stderr).strip().splitlines()[0] if (completed.stdout or completed.stderr).strip() else None
    if completed.returncode != 0 or not version:
        return enrich_tool_status(
            {
            "tool": tool,
            "status": "skipped",
            "available": False,
            "version": None,
            "command": [tool, *version_args],
            "phase": "0",
            "policy": "skipped",
            "exit_code": completed.returncode,
            "skipped_reason": f"{tool} version command failed",
            "notes": [str(command_path)],
            },
            capability=f"{tool}_version_probe",
            provenance_class="core-optional",
        )
    return enrich_tool_status(
        {
        "tool": tool,
        "status": "detected",
        "available": True,
        "version": version,
        "command": [tool, *version_args],
        "phase": "0",
        "policy": "allowed",
        "exit_code": completed.returncode,
        "notes": [str(command_path)],
        },
        capability=f"{tool}_version_probe",
        provenance_class="core-optional",
    )


def detect_python() -> dict[str, Any]:
    return enrich_tool_status(
        {
        "tool": "python",
        "status": "detected",
        "available": True,
        "version": sys.version.split()[0],
        "command": [sys.executable, "--version"],
        "phase": "0",
        "policy": "allowed",
        "exit_code": 0,
        "notes": [],
        },
        capability="python_runtime",
        provenance_class="core",
    )


def detect_sqlite_fts5() -> dict[str, Any]:
    try:
        with sqlite3.connect(":memory:") as connection:
            connection.execute("CREATE VIRTUAL TABLE fts_probe USING fts5(content)")
    except sqlite3.Error as exc:
        return enrich_tool_status(
            {
            "tool": "sqlite_fts5",
            "status": "skipped",
            "available": False,
            "version": None,
            "command": ["python", "-c", "sqlite3 fts5 probe"],
            "phase": "0",
            "policy": "skipped",
            "exit_code": None,
            "skipped_reason": f"SQLite FTS5 unavailable: {exc}",
            "notes": [f"sqlite_version={sqlite3.sqlite_version}"],
            },
            capability="sqlite_fts5",
            provenance_class="core",
        )
    return enrich_tool_status(
        {
        "tool": "sqlite_fts5",
        "status": "detected",
        "available": True,
        "version": sqlite3.sqlite_version,
        "command": ["python", "-c", "sqlite3 fts5 probe"],
        "phase": "0",
        "policy": "allowed",
        "exit_code": 0,
        "notes": [],
        },
        capability="sqlite_fts5",
        provenance_class="core",
    )


def progress_markdown() -> str:
    lines = [
        "# Audit Progress",
        "",
        "Current phase: 0 Bootstrap Sicuro",
        "",
        "| Phase | Name | Status |",
        "|---:|---|---|",
    ]
    lines.extend(f"| {number} | {name} | pending |" for number, name in PHASES)
    return "\n".join(lines) + "\n"


def bootstrap_audit(run_config: dict[str, Any], cwd: Path | None = None) -> Path:
    base = (cwd or Path.cwd()).resolve()
    run_config.setdefault("schema_version", "1.1")
    run_config.setdefault("launch_surface", build_launch_surface())
    audit_dir = resolve_output_dir(str(run_config["output_dir"]), base)
    audit_dir.mkdir(parents=True, exist_ok=True)

    provenance = run_config.setdefault("provenance", {})
    config_path_value = provenance.get("config_path")
    if config_path_value:
        config_path = Path(str(config_path_value))
        if config_path.exists():
            snapshot_hash = copy_snapshot(config_path, audit_dir / ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"])
            provenance["config_snapshot_path"] = ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"]
            provenance["config_snapshot_sha256"] = snapshot_hash
            if provenance.get("config_sha256") and provenance["config_sha256"] != snapshot_hash:
                raise BootstrapError("config snapshot hash does not match normalized config hash")

    tools = [detect_python(), detect_command("git", ["--version"], allowed_root=base), detect_command("rg", ["--version"], allowed_root=base), detect_sqlite_fts5()]

    network_policy_path = Path(str(run_config.get("network_policy_file") or ARTIFACT_PATHS["NETWORK_POLICY"]))
    if not network_policy_path.is_absolute():
        network_policy_path = base / network_policy_path
    if network_policy_path.exists():
        network_hash = copy_snapshot(network_policy_path, audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"])
        provenance["network_policy_snapshot_path"] = ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]
        provenance["network_policy_snapshot_sha256"] = network_hash
        tools.append(
            enrich_tool_status(
                {
                "tool": "network_policy",
                "status": "detected",
                "available": True,
                "version": "snapshot",
                "command": [],
                "phase": "0",
                "policy": "allowed",
                "exit_code": 0,
                "notes": [str(network_policy_path)],
                },
                capability="network_governance",
                provenance_class="core",
            )
        )
    else:
        tools.append(
            enrich_tool_status(
                {
                "tool": "network_policy",
                "status": "skipped",
                "available": False,
                "version": None,
                "command": [],
                "phase": "0",
                "policy": "skipped",
                "exit_code": None,
                "skipped_reason": "network policy missing; network adapters blocked",
                "notes": [],
                },
                capability="network_governance",
                provenance_class="core",
            )
        )

    write_json(audit_dir / ARTIFACT_PATHS["RUN_CONFIG"], run_config)
    write_json(audit_dir / ARTIFACT_PATHS["TOOL_STATUS"], {"schema_version": "1.0", "tools": tools})
    (audit_dir / ARTIFACT_PATHS["PROGRESS"]).write_text(progress_markdown(), encoding="utf-8")
    write_json(audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"], {"schema_version": "1.0", "attempts": []})
    return audit_dir


def load_run_config_for_bootstrap(args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    overrides = ArgvOverrides(
        command="run",
        argv=argv,
        profile=args.profile,
        output_dir=args.output_dir,
        allowed_roots=tuple(args.allowed_root or []),
        dry_run=False,
    )
    if args.config and args.run_config:
        raise ConfigError("use exactly one primary source: --config or --run-config, not both")
    if args.run_config:
        return load_run_config(Path(args.run_config), overrides)
    if args.config:
        config_path = Path(args.config)
        return normalize_run_config(load_config_file(config_path), overrides, config_path)
    raise ConfigError("missing primary source: pass --config or --run-config")


def main(argv: list[str] | None = None) -> int:
    actual_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="audit_bootstrap.py")
    parser.add_argument("--config")
    parser.add_argument("--run-config")
    parser.add_argument("--profile")
    parser.add_argument("--output-dir")
    parser.add_argument("--allowed-root", action="append", default=[])
    args = parser.parse_args(actual_argv)
    try:
        audit_dir = bootstrap_audit(load_run_config_for_bootstrap(args, actual_argv))
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"bootstrapped {audit_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
