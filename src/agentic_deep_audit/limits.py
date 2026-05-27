"""Shared limits for reading untrusted repository files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


MAX_AUDIT_FILE_BYTES = 25_000_000
MAX_MANIFEST_FILE_BYTES = 1_000_000


class FileSizeLimitError(ValueError):
    """Raised when an untrusted file exceeds the configured audit read cap."""


class JsonDepthLimitError(FileSizeLimitError):
    """Raised when JSON parsing exceeds the interpreter nesting limit."""


def ensure_file_size(path: Path, max_bytes: int, label: str) -> int:
    if path.is_symlink():
        raise FileSizeLimitError(f"{label} is a symlink")
    size = path.stat().st_size
    if size > max_bytes:
        raise FileSizeLimitError(f"{label} exceeds size cap: {size} > {max_bytes} bytes")
    return size


def read_bytes_capped(path: Path, max_bytes: int = MAX_AUDIT_FILE_BYTES, label: str = "file") -> bytes:
    ensure_file_size(path, max_bytes, label)
    return path.read_bytes()


def read_text_capped(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str | None = None,
    max_bytes: int = MAX_AUDIT_FILE_BYTES,
    label: str = "file",
) -> str:
    ensure_file_size(path, max_bytes, label)
    return path.read_text(encoding=encoding, errors=errors)


def decode_text_bytes(data: bytes, *, encoding: str = "utf-8", errors: str | None = None) -> str:
    error_mode = "strict" if errors is None else errors
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors=error_mode)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors=error_mode)
    return data.decode(encoding, errors=error_mode)


def read_text_auto_capped(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str | None = None,
    max_bytes: int = MAX_AUDIT_FILE_BYTES,
    label: str = "file",
) -> str:
    return decode_text_bytes(read_bytes_capped(path, max_bytes, label), encoding=encoding, errors=errors)


def read_json_capped(path: Path, *, max_bytes: int = MAX_AUDIT_FILE_BYTES, label: str = "json artifact") -> Any:
    try:
        return json.loads(read_text_auto_capped(path, encoding="utf-8", max_bytes=max_bytes, label=label))
    except RecursionError as exc:
        raise JsonDepthLimitError(f"{label} exceeds JSON parser depth budget") from exc


def sha256_file_capped(path: Path, max_bytes: int = MAX_AUDIT_FILE_BYTES, label: str = "file") -> str:
    ensure_file_size(path, max_bytes, label)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
