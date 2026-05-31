from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentic_deep_audit.adapters.base import append_tool_status
from agentic_deep_audit.artifact_io import ArtifactSchemaError, artifact_key_for_path, write_json_artifact
from agentic_deep_audit.config import write_run_config
from agentic_deep_audit.models import ARTIFACT_PATHS, RUN_CONFIG


WRITER_MODULES = [
    "agentic_deep_audit.audit_canonical_graph",
    "agentic_deep_audit.audit_corpus",
    "agentic_deep_audit.audit_evidence",
    "agentic_deep_audit.audit_graph",
    "agentic_deep_audit.audit_inventory",
    "agentic_deep_audit.audit_license_binary",
    "agentic_deep_audit.audit_manifest",
    "agentic_deep_audit.audit_mcp_export",
    "agentic_deep_audit.audit_provenance",
    "agentic_deep_audit.audit_quality",
    "agentic_deep_audit.audit_reuse",
    "agentic_deep_audit.audit_risk",
    "agentic_deep_audit.audit_scientific",
    "agentic_deep_audit.audit_surface",
    "agentic_deep_audit.audit_synthesis",
    "agentic_deep_audit.audit_telemetry",
    "agentic_deep_audit.bootstrap",
]


def test_artifact_key_for_path_resolves_nested_registered_artifacts(tmp_path: Path) -> None:
    assert artifact_key_for_path(tmp_path / ARTIFACT_PATHS["GRAPH"]) == "GRAPH"
    assert artifact_key_for_path(tmp_path / ARTIFACT_PATHS["MCP_CONFIG"]) == "MCP_CONFIG"
    assert artifact_key_for_path(tmp_path / "scratch.json") is None


def test_unregistered_json_path_preserves_plain_write_behavior(tmp_path: Path) -> None:
    path = tmp_path / "scratch.json"

    write_json_artifact(path, {"not": "schema-backed"})

    assert json.loads(path.read_text(encoding="utf-8")) == {"not": "schema-backed"}


@pytest.mark.parametrize("module_name", WRITER_MODULES)
def test_local_json_writers_reject_invalid_registered_artifacts(module_name: str, tmp_path: Path) -> None:
    module = importlib.import_module(module_name)
    path = tmp_path / ARTIFACT_PATHS["RISK_FINDINGS"]

    with pytest.raises(ArtifactSchemaError, match="RISK_FINDINGS\\.json failed risk_findings schema"):
        module.write_json(path, {"schema_version": "1.0"})

    assert not path.exists()


def test_write_run_config_rejects_invalid_registered_artifact(tmp_path: Path) -> None:
    run_config = {"schema_version": "1.0", "output_dir": str(tmp_path)}

    with pytest.raises(ArtifactSchemaError, match="RUN_CONFIG\\.json failed run_config schema"):
        write_run_config(run_config)

    assert not (tmp_path / RUN_CONFIG).exists()


def test_append_tool_status_rejects_invalid_registered_artifact(tmp_path: Path) -> None:
    with pytest.raises(ArtifactSchemaError, match="TOOL_STATUS\\.json failed tool_status schema"):
        append_tool_status(tmp_path, {"tool": "bad"})

    assert not (tmp_path / ARTIFACT_PATHS["TOOL_STATUS"]).exists()


def test_write_json_artifact_creates_missing_parent_directories(tmp_path: Path) -> None:
    # OQ-M26-01/02: the non-atomic write path must create missing parents like the atomic path
    # already does, so write_json_artifact is safe regardless of which writer calls it (no silent
    # dependence on every caller pre-creating the directory).
    path = tmp_path / "nested" / "deeper" / "scratch.json"

    write_json_artifact(path, {"created": True})

    assert json.loads(path.read_text(encoding="utf-8")) == {"created": True}
