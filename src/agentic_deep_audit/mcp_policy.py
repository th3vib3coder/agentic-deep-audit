"""MCP host metadata redaction helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse


SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]+"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bBearer\s+\S{8,}\b", re.IGNORECASE),
]
MAX_REDACTION_DEPTH = 256


def _high_entropy(value: str) -> bool:
    if len(value) < 20:
        return False
    unique_ratio = len(set(value)) / len(value)
    return unique_ratio > 0.55 and bool(re.search(r"[A-Z]", value)) and bool(re.search(r"[a-z]", value)) and bool(re.search(r"\d", value))


def looks_secret(value: str) -> bool:
    if re.fullmatch(r"run-\d{8}T\d{6}Z", value):
        return False
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        return True
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        return True
    return _high_entropy(value)


def redact_value(value: object) -> object:
    if not isinstance(value, str):
        return value
    if not looks_secret(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"<redacted sha256:{digest}>"


def redact_host_metadata(data: object, depth: int = 0) -> object:
    if depth > MAX_REDACTION_DEPTH:
        return "<redacted:depth-limit>"
    if isinstance(data, dict):
        return {key: redact_host_metadata(value, depth + 1) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_host_metadata(item, depth + 1) for item in data]
    return redact_value(data)
