from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import agentic_deep_audit.audit_surface as audit_surface
from agentic_deep_audit.limits import FileSizeLimitError
from agentic_deep_audit.audit_graph import run_graph
from agentic_deep_audit.audit_inventory import run_inventory
from agentic_deep_audit.audit_manifest import run_manifest
from agentic_deep_audit.audit_surface import run_surface
from agentic_deep_audit.audit_validate import validate_audit, validate_surface_artifacts
from agentic_deep_audit.bootstrap import bootstrap_audit
from agentic_deep_audit.models import ARTIFACT_PATHS


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PLUGIN_ROOT / "src"
FIXTURES = PLUGIN_ROOT / "tests" / "fixtures"


def copy_fixture(name: str, tmp_path: Path) -> Path:
    target = tmp_path / name
    shutil.copytree(FIXTURES / name, target)
    return target


def config_for(repo: Path, output: Path) -> dict:
    return {
        "schema_version": "1.0",
        "run_id": "run-surface",
        "repo": {"kind": "local", "path": str(repo), "github": None},
        "profile": "minimal",
        "mode": "source-audit",
        "output_dir": str(output),
        "scope_filters": {"include": ["**/*"], "exclude": [".git/**", "node_modules/**"]},
        "target_context": {"preset": "MIT downstream"},
        "binary_triage_consent": False,
        "graph": {"centrality": {"algorithm": "weighted_in_degree", "normal_import_weight": 1.0, "conditional_import_weight": 0.5, "tie_break": ["size_bytes_desc", "path_normalized_asc"]}},
    }


def build_surface(repo: Path, output: Path) -> Path:
    run_config = config_for(repo, output)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(run_config, indent=2) + "\n", encoding="utf-8")
    run_config["provenance"] = {"config_path": str(config_path)}
    audit_dir = bootstrap_audit(run_config, cwd=repo)
    run_inventory(run_config, audit_dir)
    run_manifest(run_config, audit_dir)
    run_graph(run_config, audit_dir)
    run_surface(run_config, audit_dir)
    return audit_dir


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_api_surface_extracts_rest_graphql_grpc_and_websocket_routes(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir = build_surface(repo, repo / "audit")
    api = load_json(audit_dir / ARTIFACT_PATHS["API_SURFACE"])["records"]

    assert any(item["method"] == "GET" and item["path"] == "/health" and item["framework"] == "fastapi_or_flask_decorator" and item["evidence_ids"] for item in api)
    assert any(item["method"] == "POST" and item["path"] == "/submit" and item["framework"] == "js_router" and item["evidence_ids"] for item in api)
    assert any(item["framework"] == "graphql" and item["status"] == "heuristic" for item in api)
    assert any(item["framework"] == "grpc" and item["path"] == "grpc://AuditService" for item in api)
    assert any(item["method"] == "WEBSOCKET" for item in api)
    assert validate_audit(audit_dir).ok


def test_cli_surface_records_entrypoints_without_execution(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir = build_surface(repo, repo / "audit-cli")
    cli = load_json(audit_dir / ARTIFACT_PATHS["CLI_SURFACE"])["records"]

    assert any(item["kind"] == "manifest_script" and item["command"] == "surface_app:main" for item in cli)
    assert any(item["kind"] == "manifest_script" and item["command"] == "node src/index.ts" for item in cli)
    assert any(item["kind"] == "node_bin" and item["name"] == "surface-js" for item in cli)
    assert any(item["kind"] == "cargo_bin" and item["name"] == "surface-rs" for item in cli)
    assert any(item["kind"] == "go_command" and item["name"] == "surface" for item in cli)
    assert any(item["kind"] == "python_main_guard" and item["entrypoint"] == "src/api.py" for item in cli)
    assert all(item["executable"] is False and item["observed_not_executed"] is True for item in cli)


def test_cli_surface_skips_oversized_manifest_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"bin": {"tool": "cli.js"}}\n', encoding="utf-8")
    (repo / "Cargo.toml").write_text("[[bin]]\nname = 'tool'\n", encoding="utf-8")

    def raise_size_limit(*_args, **_kwargs):
        raise FileSizeLimitError("test cap")

    monkeypatch.setattr(audit_surface, "read_text_auto_capped", raise_size_limit)

    assert audit_surface.package_bin_records(repo, {"package.json": ["ev-000001"]}, 0) == []
    assert audit_surface.cargo_bin_records(repo, {"Cargo.toml": ["ev-000002"]}, 0) == []


def test_mcp_surface_is_audit_data_only_and_not_host_imported(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir = build_surface(repo, repo / "audit-mcp")
    mcp = load_json(audit_dir / ARTIFACT_PATHS["MCP_SURFACE"])["records"]

    assert mcp
    assert mcp[0]["source_path"] == ".mcp.json"
    assert mcp[0]["server_names"] == ["target-tool"]
    assert mcp[0]["host_imported"] is False
    assert not (audit_dir / ARTIFACT_PATHS["MCP_CONFIG"]).exists()


def test_config_surface_records_env_names_without_host_values(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgres://secret")
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir = build_surface(repo, repo / "audit-config")
    config = load_json(audit_dir / ARTIFACT_PATHS["CONFIG_SURFACE"])["records"]

    env_records = [item for item in config if item["kind"] == "env_var"]
    assert {item["name"] for item in env_records} >= {"APP_STATUS", "PORT", "DATABASE_URL", "API_TOKEN", "OPTIONAL_FLAG"}
    assert all(item.get("value_read") is False for item in env_records)
    assert all("postgres://secret" not in json.dumps(item) for item in env_records)
    assert "fixture-secret" not in json.dumps(config)
    assert "must_not_count" not in {item["name"] for item in env_records}
    readme = next(item for item in env_records if item["name"] == "DATABASE_URL")
    assert readme["source_path"] == "README.md"
    assert readme["sanitizer_decision"] in {"quoted_with_flags", "blocked_from_llm_context"}


def test_surface_validator_rejects_unsanitized_markdown_surface(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    audit_dir = build_surface(repo, repo / "audit-validation")
    config_path = audit_dir / ARTIFACT_PATHS["CONFIG_SURFACE"]
    payload = load_json(config_path)
    payload["records"].append(
        {
            "surface_id": "config-bad",
            "kind": "env_var",
            "source_path": "README.md",
            "status": "heuristic",
            "confidence": "medium",
            "evidence_ids": payload["records"][0]["evidence_ids"],
            "sanitizer_decision": "unsanitized",
            "name": "BAD_ENV",
            "value_read": False,
        }
    )
    config_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    validation = validate_surface_artifacts(audit_dir)

    assert not validation.ok
    assert any("Markdown-derived surface lacks sanitizer decision" in error for error in validation.errors)


def test_cli_surface_command_wires_phase_outputs(tmp_path: Path) -> None:
    repo = copy_fixture("surface_basic", tmp_path)
    config_path = repo / "audit.config.json"
    config_path.write_text(json.dumps(config_for(repo, repo / "audit-cli-command"), indent=2) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_ROOT)

    result = subprocess.run(
        [sys.executable, "-m", "agentic_deep_audit.cli", "surface", "--config", str(config_path)],
        cwd=repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    audit_dir = repo / "audit-cli-command"
    for artifact in ["API_SURFACE", "CLI_SURFACE", "MCP_SURFACE", "CONFIG_SURFACE"]:
        assert (audit_dir / ARTIFACT_PATHS[artifact]).exists()
