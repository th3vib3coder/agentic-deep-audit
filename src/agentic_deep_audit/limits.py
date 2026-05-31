"""Shared limits for reading untrusted repository files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
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
    normalize_newlines: bool = False,
) -> str:
    text = decode_text_bytes(read_bytes_capped(path, max_bytes, label), encoding=encoding, errors=errors)
    if normalize_newlines:
        # Opt-in only: callers that care about exact byte offsets (evidence ranges, hashes) keep
        # the default (no rewrite). CRLF and lone CR both collapse to LF.
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def read_json_capped(path: Path, *, max_bytes: int = MAX_AUDIT_FILE_BYTES, label: str = "json artifact") -> Any:
    try:
        return json.loads(read_text_auto_capped(path, encoding="utf-8", max_bytes=max_bytes, label=label))
    except RecursionError as exc:
        raise JsonDepthLimitError(f"{label} exceeds JSON parser depth budget") from exc


def is_safe_repo_relative_path(path_value: str) -> bool:
    if not path_value or "\\" in path_value or ":" in path_value or "\x00" in path_value:
        return False
    posix_path = PurePosixPath(path_value)
    windows_path = PureWindowsPath(path_value)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive or windows_path.root:
        return False
    return ".." not in posix_path.parts and ".." not in windows_path.parts


def resolve_repo_file(repo_path: Path, path_value: str) -> Path | None:
    if not is_safe_repo_relative_path(path_value):
        return None
    root = repo_path.resolve()
    candidate = (root / path_value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def resolve_repo_existing_file(repo_path: Path, path_value: str) -> Path | None:
    candidate = resolve_repo_file(repo_path, path_value)
    if candidate is None or not candidate.is_file():
        return None
    return candidate


def sha256_file_capped(path: Path, max_bytes: int = MAX_AUDIT_FILE_BYTES, label: str = "file") -> str:
    ensure_file_size(path, max_bytes, label)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
