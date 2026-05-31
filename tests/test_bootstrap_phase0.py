from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentic_deep_audit import bootstrap as bootstrap_module
from agentic_deep_audit.audit_validate import validate_audit, validate_phase0
from agentic_deep_audit.bootstrap import PHASES, BootstrapError, copy_snapshot
from agentic_deep_audit.config import sha256_file
from agentic_deep_audit.limits import FileSizeLimitError
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
BOOTSTRAP_SCRIPT = PLUGIN_ROOT / "skills" / "deep-repo-audit" / "scripts" / "audit_bootstrap.py"


def cli_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)
    return env


def write_config(tmp_path: Path, output_dir: str | None = None, network_policy_file: str | None = None) -> Path:
    lines = [
        'schema_version: "1.0"',
        "repo:",
        '  kind: "local"',
        '  path: "."',
        "  github: null",
        'profile: "minimal"',
        'mode: "source-audit"',
        f'output_dir: "{output_dir or "audit"}"',
        'target_context: "MIT downstream"',
        "binary_triage_consent: false",
    ]
    if network_policy_file:
        lines.append(f'network_policy_file: "{network_policy_file}"')
    config = tmp_path / "audit.config.yaml"
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", *args],
        cwd=cwd,
        env=cli_env(),
        check=False,
        text=True,
        capture_output=True,
    )


def test_copy_snapshot_wraps_read_oserror_as_bootstrap_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # CFG-001: copy_snapshot wraps the size-cap failure (FileSizeLimitError) as BootstrapError,
    # but a raw OSError from the underlying read (TOCTOU: the file removed/locked after the
    # existence check) escaped unwrapped, losing the "snapshot read failed: <source>" context.
    # Both failure modes of the same read must surface as BootstrapError.
    source = tmp_path / "audit.config.yaml"
    source.write_text("schema_version: '1.0'\n", encoding="utf-8")
    destination = tmp_path / "audit" / ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"]

    def boom(*args: object, **kwargs: object) -> bytes:
        raise OSError("simulated post-stat read failure")

    monkeypatch.setattr(bootstrap_module, "read_bytes_capped", boom)

    with pytest.raises(BootstrapError):
        copy_snapshot(source, destination)


def test_phase0_bootstrap_creates_only_phase0_artifacts(tmp_path: Path) -> None:
    config = write_config(tmp_path)

    result = subprocess.run(
        [sys.executable, str(BOOTSTRAP_SCRIPT), "--config", str(config)],
        cwd=tmp_path,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"
    expected = {
        ARTIFACT_PATHS["RUN_CONFIG"],
        ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"],
        ARTIFACT_PATHS["TOOL_STATUS"],
        ARTIFACT_PATHS["PROGRESS"],
        ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"],
    }
    assert {path.name for path in audit_dir.iterdir()} == expected
    run_config = json.loads((audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).read_text(encoding="utf-8"))
    assert run_config["provenance"]["config_snapshot_sha256"] == sha256_file(config)
    assert sha256_file(audit_dir / ARTIFACT_PATHS["AUDIT_CONFIG_SNAPSHOT"]) == sha256_file(config)
    assert validate_phase0(audit_dir).ok


def test_bootstrap_phase0_emits_launch_surface(tmp_path: Path) -> None:
    config = write_config(tmp_path)

    result = subprocess.run(
        [sys.executable, str(BOOTSTRAP_SCRIPT), "--config", str(config)],
        cwd=tmp_path,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"
    run_config = json.loads((audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).read_text(encoding="utf-8"))
    assert run_config["schema_version"] == "1.1"
    launch_surface = run_config["launch_surface"]
    assert {"adapter", "adapter_version", "entry_command", "host_os", "cwd_policy"} <= set(launch_surface)


def test_missing_network_policy_is_skipped_and_validate_rejects_missing_run_config(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = run_cli("run", "--config", str(config), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"

    tool_status = json.loads((audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))
    network = next(tool for tool in tool_status["tools"] if tool["tool"] == "network_policy")
    assert network["status"] == "skipped"
    assert "network adapters blocked" in network["skipped_reason"]

    (audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).unlink()
    validation = validate_phase0(audit_dir)
    assert not validation.ok
    assert any("RUN_CONFIG.json" in error for error in validation.errors)


def test_network_policy_snapshot_when_present(tmp_path: Path) -> None:
    policy = tmp_path / ".network_policy.json"
    policy.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "default": "deny",
                "allowed_domains": ["api.github.com"],
                "denied_domains": ["*"],
                "send_source_code": False,
                "rate_limits": [],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    config = write_config(tmp_path, network_policy_file=".network_policy.json")

    result = run_cli("run", "--config", str(config), cwd=tmp_path)

    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"
    run_config = json.loads((audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).read_text(encoding="utf-8"))
    assert run_config["provenance"]["network_policy_snapshot_sha256"] == sha256_file(policy)
    assert sha256_file(audit_dir / ARTIFACT_PATHS["NETWORK_POLICY_SNAPSHOT"]) == sha256_file(policy)
    assert validate_phase0(audit_dir).ok


def test_copy_snapshot_uses_capped_reader(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "snapshot-source.json"
    destination = tmp_path / "snapshot-copy.json"
    source.write_bytes(b"uncapped original")
    calls: list[tuple[Path, str | None]] = []

    def capped_read(path: Path, **kwargs: object) -> bytes:
        calls.append((path, kwargs.get("label") if isinstance(kwargs.get("label"), str) else None))
        return b"capped bytes"

    monkeypatch.setattr(bootstrap_module, "read_bytes_capped", capped_read)

    snapshot_hash = copy_snapshot(source, destination)

    assert calls == [(source, "bootstrap snapshot")]
    assert destination.read_bytes() == b"capped bytes"
    assert snapshot_hash == sha256_file(destination)


def test_copy_snapshot_converts_size_cap_to_bootstrap_error(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "snapshot-source.json"
    destination = tmp_path / "snapshot-copy.json"
    source.write_bytes(b"oversized")

    def fail_on_read(path: Path, **kwargs: object) -> bytes:
        raise FileSizeLimitError("bootstrap snapshot exceeds size cap: 10 > 1 bytes")

    monkeypatch.setattr(bootstrap_module, "read_bytes_capped", fail_on_read)

    with pytest.raises(BootstrapError, match="snapshot read failed: .*exceeds size cap"):
        copy_snapshot(source, destination)

    assert not destination.exists()


def test_bootstrap_main_reports_oversized_snapshot_without_traceback(tmp_path: Path, monkeypatch, capsys) -> None:
    policy = tmp_path / ".network_policy.json"
    policy.write_text('{"schema_version":"1.0"}\n', encoding="utf-8")
    config = write_config(tmp_path, network_policy_file=".network_policy.json")

    def capped_read(path: Path, **kwargs: object) -> bytes:
        if path == policy:
            raise FileSizeLimitError("bootstrap snapshot exceeds size cap: 10 > 1 bytes")
        return path.read_bytes()

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(bootstrap_module, "read_bytes_capped", capped_read)

    exit_code = bootstrap_module.main(["--config", str(config)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "error: snapshot read failed:" in captured.err
    assert "exceeds size cap" in captured.err
    assert "Traceback" not in captured.err


def test_tool_status_records_version_or_skip_reason_and_progress_phases(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = run_cli("run", "--config", str(config), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"

    tool_status = json.loads((audit_dir / ARTIFACT_PATHS["TOOL_STATUS"]).read_text(encoding="utf-8"))
    for tool in tool_status["tools"]:
        if tool["status"] == "detected":
            assert tool["version"]
        if tool["status"] == "skipped":
            assert tool["skipped_reason"]

    progress = (audit_dir / ARTIFACT_PATHS["PROGRESS"]).read_text(encoding="utf-8")
    assert "Current phase: 0 Bootstrap Sicuro" in progress
    for number, name in PHASES:
        assert f"| {number} | {name} | pending |" in progress

    blocked = json.loads((audit_dir / ARTIFACT_PATHS["BLOCKED_COMMANDS_ATTEMPTS"]).read_text(encoding="utf-8"))
    assert blocked == {"schema_version": "1.0", "attempts": []}


def test_validate_audit_requires_artifacts_for_completed_progress_phases(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = subprocess.run(
        [sys.executable, str(BOOTSTRAP_SCRIPT), "--config", str(config)],
        cwd=tmp_path,
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    audit_dir = tmp_path / "audit"
    progress_path = audit_dir / ARTIFACT_PATHS["PROGRESS"]
    progress = progress_path.read_text(encoding="utf-8")
    progress_path.write_text(progress.replace("| 1 | Inventory E Provenance | pending |", "| 1 | Inventory E Provenance | complete |"), encoding="utf-8")

    validation = validate_audit(audit_dir)

    assert not validation.ok
    assert any("phase 1 Inventory E Provenance declared complete" in error and "FILE_INDEX.json" in error for error in validation.errors)


def test_bootstrap_rejects_output_outside_allowed_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    config = write_config(tmp_path, output_dir=str(outside))

    result = run_cli("run", "--config", str(config), cwd=tmp_path)

    assert result.returncode == 2
    assert "outside allowed root" in result.stderr
    assert not outside.exists()


def test_bootstrap_script_uses_same_runtime_path(tmp_path: Path) -> None:
    config = write_config(tmp_path)

    result = subprocess.run(
        [sys.executable, str(BOOTSTRAP_SCRIPT), "--config", str(config)],
        cwd=tmp_path,
        check=False,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert validate_phase0(tmp_path / "audit").ok
