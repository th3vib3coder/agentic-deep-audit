from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from agentic_deep_audit.models import ARTIFACT_PATHS, SCHEMA_FILES, SchemaRegistryError, load_schema_registry


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ARTIFACTS_REFERENCE = PLUGIN_ROOT / "skills" / "deep-repo-audit" / "references" / "output_artifacts.md"


def documented_artifacts() -> set[str]:
    reference = OUTPUT_ARTIFACTS_REFERENCE.read_text(encoding="utf-8")
    return set(re.findall(r"`([^`]+)`", reference))


def test_artifact_constants_cover_output_reference() -> None:
    values = set(ARTIFACT_PATHS.values())
    missing = sorted(documented_artifacts() - values)
    undocumented = sorted(values - documented_artifacts())

    assert not missing
    assert not undocumented


def test_schema_registry_loads_all_bundled_schema_json() -> None:
    registry = load_schema_registry()

    assert set(registry) == set(SCHEMA_FILES)
    for record in registry.values():
        assert record.path.exists()
        assert record.schema["type"] == "object"


def test_schema_registry_reports_corrupt_schema_path_and_name(tmp_path: Path) -> None:
    schema_dir = tmp_path / "schemas"
    shutil.copytree(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "schemas", schema_dir)
    corrupt = schema_dir / SCHEMA_FILES["tool_status"]
    corrupt.write_text("{not-json", encoding="utf-8")

    with pytest.raises(SchemaRegistryError) as exc:
        load_schema_registry(schema_dir)

    message = str(exc.value)
    assert "tool_status" in message
    assert str(corrupt) in message


def test_schema_registry_reports_structural_schema_error_path_and_name(tmp_path: Path) -> None:
    schema_dir = tmp_path / "schemas"
    shutil.copytree(PLUGIN_ROOT / "skills" / "deep-repo-audit" / "schemas", schema_dir)
    corrupt = schema_dir / SCHEMA_FILES["tool_status"]
    corrupt.write_text('{"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "properties": {}}', encoding="utf-8")

    with pytest.raises(SchemaRegistryError) as exc:
        load_schema_registry(schema_dir)

    message = str(exc.value)
    assert "tool_status" in message
    assert str(corrupt) in message
    assert "missing schema key title" in message


def test_no_runtime_artifact_string_outside_models() -> None:
    runtime_files = [
        PLUGIN_ROOT / "src" / "agentic_deep_audit" / "cli.py",
        PLUGIN_ROOT / "src" / "agentic_deep_audit" / "config.py",
    ]
    forbidden = sorted(value for value in ARTIFACT_PATHS.values() if "/" not in value and "*" not in value)

    for path in runtime_files:
        text = path.read_text(encoding="utf-8")
        for artifact in forbidden:
            assert artifact not in text, f"{artifact} is hardcoded in {path}"
