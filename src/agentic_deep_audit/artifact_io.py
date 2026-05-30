"""Shared audit artifact writers."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import ARTIFACT_PATHS, load_schema_registry
from .validate_json_schema import SCHEMA_BY_ARTIFACT_KEY


class ArtifactSchemaError(ValueError):
    """Raised before writing a JSON artifact that violates its registered schema."""


@lru_cache(maxsize=1)
def _schema_registry() -> dict[str, dict[str, Any]]:
    return {name: record.schema for name, record in load_schema_registry().items()}


def artifact_key_for_path(path: Path) -> str | None:
    path_value = path.as_posix()
    # Match the longest registered relative path first so a nested artifact (e.g. graph/graph.json)
    # is never shadowed by a shorter registered path that is a suffix of it (OQ-M26-03).
    for key, relative in sorted(ARTIFACT_PATHS.items(), key=lambda item: len(item[1]), reverse=True):
        if "*" in relative:
            continue
        normalized = relative.replace("\\", "/")
        if path_value == normalized or path_value.endswith(f"/{normalized}"):
            return key
    return None


def validate_json_payload_for_path(path: Path, payload: dict[str, Any]) -> None:
    artifact_key = artifact_key_for_path(path)
    if artifact_key is None:
        return
    schema_name = SCHEMA_BY_ARTIFACT_KEY.get(artifact_key)
    if schema_name is None:
        return
    from jsonschema import Draft202012Validator

    schema = _schema_registry()[schema_name]
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.path))
    if not errors:
        return
    first = errors[0]
    location = ".".join(str(part) for part in first.path) or "<root>"
    relative = ARTIFACT_PATHS[artifact_key]
    raise ArtifactSchemaError(f"{relative} failed {schema_name} schema at {location}: {first.message}")


def write_json_artifact(path: Path, payload: dict[str, Any], *, atomic: bool = False) -> None:
    validate_json_payload_for_path(path, payload)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not atomic:
        path.write_text(text, encoding="utf-8")
        return
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
