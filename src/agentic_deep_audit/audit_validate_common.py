"""Shared validation primitives."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import FileSizeLimitError, read_text_auto_capped


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str]


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    if not path.exists():
        errors.append(f"missing required artifact: {path}")
        return None
    if path.is_symlink():
        errors.append(f"invalid JSON artifact: {path}: symlink artifacts are not allowed")
        return None
    try:
        payload = json.loads(read_text_auto_capped(path, encoding="utf-8", label="json artifact"))
    except FileSizeLimitError as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    except json.JSONDecodeError as exc:
        errors.append(f"invalid JSON artifact: {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"artifact root must be object: {path}")
        return None
    return payload
