"""Untrusted Markdown sanitizer."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


BLOCK_PATTERNS = {
    "hidden_tag": re.compile(r"</?(system|assistant|developer|tool)\b[^>]*>", re.IGNORECASE),
    "override_marker": re.compile(r"ignore\s+previous|developer\s+instruction|system\s+prompt|do\s+not\s+tell\s+user", re.IGNORECASE),
    "zero_width": re.compile("[\u200b\u200c\u200d\ufeff]"),
    "base64_like": re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
    "secret_request": re.compile(r"\b(env vars?|home directory|token|secret|api key)\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class SanitizedMarkdown:
    sanitized_text: str
    flagged_ranges: list[dict[str, object]]
    raw_reference: dict[str, object]
    decision: str


def sanitize_markdown(path: str, markdown_text: str, start_byte: int = 0, evidence_id: str | None = None) -> SanitizedMarkdown:
    flags: list[dict[str, object]] = []
    for kind, pattern in BLOCK_PATTERNS.items():
        for match in pattern.finditer(markdown_text):
            flags.append({"kind": kind, "start_byte": start_byte + match.start(), "end_byte": start_byte + match.end(), "severity": "critical" if kind in {"hidden_tag", "override_marker"} else "medium"})
    decision = "blocked_from_llm_context" if any(flag["kind"] in {"hidden_tag", "override_marker", "secret_request"} for flag in flags) else ("quoted_with_flags" if flags else "pass")
    quoted = "\n".join(f"> {line}" for line in markdown_text.splitlines())
    raw_reference = {
        "path": path,
        "evidence_id": evidence_id,
        "start_byte": start_byte,
        "end_byte": start_byte + len(markdown_text.encode("utf-8")),
        "raw_sha256": hashlib.sha256(markdown_text.encode("utf-8")).hexdigest(),
    }
    return SanitizedMarkdown(sanitized_text=quoted, flagged_ranges=flags, raw_reference=raw_reference, decision=decision)
