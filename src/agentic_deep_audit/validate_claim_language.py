"""Anti-overclaim checks for final audit artifacts."""

from __future__ import annotations

import re
from pathlib import Path

from .limits import FileSizeLimitError, read_text_auto_capped
from .models import ARTIFACT_PATHS


FINAL_TEXT_KEYS = ["REPORT", "RISK_REPORT", "QUALITY_REVIEW", "PERFORMANCE_REVIEW"]
ABSOLUTE_PATTERNS = [
    re.compile(r"\b100%\s+(complete|completo|sicuro|secure|accurate|accurato)\b", re.IGNORECASE),
    re.compile(r"\b(perfect|perfetto|guaranteed|garantito)\b", re.IGNORECASE),
    re.compile(r"\b(absence|assenza)\s+(totale\s+)?(of\s+)?vulnerabil", re.IGNORECASE),
    re.compile(r"\b(completely|totalmente)\s+(secure|sicuro)\b", re.IGNORECASE),
    re.compile(r"\btutte\s+le\s+feature\b", re.IGNORECASE),
]
SCOPE_QUALIFIERS = ["coverage", "scope", "profil", "within the analyzed", "rispetto allo scope", "strumenti eseguiti"]
NEGATED_CLAIM_MARKERS = ["cannot claim", "cannot guarantee", "not guarantee", "non garantire", "non promettere"]


def line_is_scoped(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in SCOPE_QUALIFIERS + NEGATED_CLAIM_MARKERS)


def validate_anti_overclaim_language(audit_dir: Path) -> list[str]:
    errors: list[str] = []
    for key in FINAL_TEXT_KEYS:
        relative = ARTIFACT_PATHS[key]
        path = audit_dir / relative
        if not path.exists():
            continue
        try:
            text = read_text_auto_capped(path, encoding="utf-8", errors="replace", label="claim language")
        except (OSError, FileSizeLimitError) as exc:
            errors.append(f"anti_overclaim: {relative}: invalid artifact: {exc}")
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            if line_is_scoped(line):
                continue
            if any(pattern.search(line) for pattern in ABSOLUTE_PATTERNS):
                errors.append(f"anti_overclaim: {relative}:{number}: absolute claim must be scoped by coverage/profile")
    return errors
