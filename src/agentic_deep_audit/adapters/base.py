"""Base adapter contract and guarded runtime helpers."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..limits import read_json_capped
from ..mcp_policy import looks_secret, redact_value
from ..models import ARTIFACT_PATHS
from ..policy import decide_command, decide_network


class AdapterError(RuntimeError):
    """Raised when an adapter cannot run safely."""


@dataclass(frozen=True)
class AdapterStatus:
    tool: str
    status: str
    policy: str
    available: bool
    version: str | None = None
    command: list[str] = field(default_factory=list)
    phase: str | None = None
    duration_ms: int | None = None
    exit_code: int | None = None
    output_path: str | None = None
    skipped_reason: str | None = None
    os: str = field(default_factory=lambda: platform.system() or "unknown")
    capability: str = "unknown"
    availability: str = "unknown"
    degradation_reason: str | None = None
    provenance_class: str = "core"
    degradation: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_tool_status_record(self) -> dict[str, Any]:
        payload = asdict(self)
        if payload.get("degradation") is None and payload.get("degradation_reason"):
            payload["degradation"] = payload["degradation_reason"]
        return {key: value for key, value in payload.items() if value is not None}


class ToolAdapter(ABC):
    adapter_id: str
    capability: str
    provenance_class: str = "core"

    def __init__(self, adapter_id: str | None = None, capability: str | None = None, provenance_class: str | None = None) -> None:
        if adapter_id is not None:
            self.adapter_id = adapter_id
        if capability is not None:
            self.capability = capability
        if provenance_class is not None:
            self.provenance_class = provenance_class

    @abstractmethod
    def detect(self) -> AdapterStatus:
        """Detect adapter availability without invoking target repo commands."""

    @abstractmethod
    def run(self, run_config: dict[str, Any], audit_dir: Path) -> AdapterStatus:
        """Run adapter under policy guards."""

    @abstractmethod
    def parse(self, raw_output_path: Path | None) -> dict[str, Any]:
        """Parse retained raw output into canonical data."""

    @abstractmethod
    def status(self) -> AdapterStatus:
        """Return the latest adapter status."""


def append_tool_status(audit_dir: Path, status: AdapterStatus | dict[str, Any]) -> None:
    path = audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]
    payload = read_json_capped(path, label="tool status") if path.exists() else {"schema_version": "1.0", "tools": []}
    record = status.to_tool_status_record() if isinstance(status, AdapterStatus) else status
    payload.setdefault("tools", []).append(record)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def resolve_contained_path(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved_candidate = (candidate if candidate.is_absolute() else resolved_root / candidate).resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise AdapterError(f"path outside containment root: {resolved_candidate}") from exc
    return resolved_candidate


def raw_output_path(audit_dir: Path, tool: str, filename: str) -> Path:
    root = audit_dir / "raw" / tool
    root.mkdir(parents=True, exist_ok=True)
    return resolve_contained_path(audit_dir, root / filename)


def persist_raw_output(audit_dir: Path, tool: str, filename: str, data: str | bytes) -> tuple[Path | None, str | None]:
    raw = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    if looks_secret(raw):
        summary_path = raw_output_path(audit_dir, tool, "REDACTED_SUMMARY.json")
        summary = {"tool": tool, "raw_persisted": False, "reason": "secret-like raw output redacted", "redacted_summary": str(redact_value(raw))}
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return None, str(summary_path.relative_to(audit_dir).as_posix())
    destination = raw_output_path(audit_dir, tool, filename)
    if isinstance(data, bytes):
        destination.write_bytes(data)
    else:
        destination.write_text(data, encoding="utf-8")
    return destination, str(destination.relative_to(audit_dir).as_posix())


def adapter_subprocess_env() -> dict[str, str]:
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


def run_adapter_command(
    adapter: ToolAdapter,
    command: list[str],
    cwd: Path,
    audit_dir: Path,
    timeout_seconds: int = 30,
    network_target: str | None = None,
    network_policy: dict[str, Any] | None = None,
    repo_root: Path | None = None,
) -> AdapterStatus:
    safe_cwd = resolve_contained_path(repo_root or cwd, cwd)
    resolve_contained_path(audit_dir, Path("."))
    decision = decide_command(command, origin="plugin_allowlist")
    if network_target and not decide_network(network_target, policy=network_policy).allowed:
        status = AdapterStatus(
            tool=adapter.adapter_id,
            status="blocked",
            policy="blocked",
            available=False,
            command=command,
            capability=adapter.capability,
            availability="blocked",
            provenance_class=adapter.provenance_class,
            degradation_reason="network policy blocked adapter request",
            skipped_reason="network policy blocked adapter request",
        )
        append_tool_status(audit_dir, status)
        return status
    if not decision.allowed:
        status = AdapterStatus(
            tool=adapter.adapter_id,
            status="blocked",
            policy="blocked",
            available=False,
            command=command,
            capability=adapter.capability,
            availability="blocked",
            provenance_class=adapter.provenance_class,
            degradation_reason=decision.reason,
            skipped_reason=decision.reason,
        )
        append_tool_status(audit_dir, status)
        return status
    start = time.monotonic()
    try:
        completed = subprocess.run(command, cwd=safe_cwd, env=adapter_subprocess_env(), text=True, capture_output=True, check=False, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        status = AdapterStatus(
            tool=adapter.adapter_id,
            status="failed",
            policy="allowed",
            available=True,
            command=command,
            capability=adapter.capability,
            availability="timeout",
            provenance_class=adapter.provenance_class,
            degradation_reason="adapter timeout",
            skipped_reason="adapter timeout",
        )
        append_tool_status(audit_dir, status)
        return status
    duration_ms = int((time.monotonic() - start) * 1000)
    _, output_path = persist_raw_output(audit_dir, adapter.adapter_id, "stdout.txt", completed.stdout)
    status = AdapterStatus(
        tool=adapter.adapter_id,
        status="completed" if completed.returncode == 0 else "failed",
        policy="allowed",
        available=True,
        command=command,
        duration_ms=duration_ms,
        exit_code=completed.returncode,
        output_path=output_path,
        capability=adapter.capability,
        availability="available",
        provenance_class=adapter.provenance_class,
        degradation_reason=None if completed.returncode == 0 else (completed.stderr.strip()[:200] or "non-zero exit"),
        notes=[f"cwd={Path(os.fspath(safe_cwd)).resolve()}"],
    )
    append_tool_status(audit_dir, status)
    return status
