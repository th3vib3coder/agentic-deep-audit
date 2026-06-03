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


def strip_quoted_table_cells(line: str) -> str:
    # FIX-GRAPHVAL (2026-06-03, hardened after swarm review): only the CONTENT of a markdown TABLE CELL that
    # is a blockquote (cell text starts with `>`) is target-repo text quoted as evidence -- the perf/quality
    # reviews embed target excerpts via sanitize_markdown's `> ` wrapping inside a table cell. Drop ONLY those
    # cells before scanning, so a target's absolute wording is not attributed to the audit, while the audit's
    # OWN claims -- in OTHER cells of the same row, or in prose (including prose blockquotes in the
    # agent-authored REPORT.md) -- are STILL scanned. (An earlier whole-line skip let an audit overclaim evade
    # via any `>`-prefixed line; the real hermes-agent FP was specifically a `| ... | > <target excerpt> |` row.)
    if "|" not in line:
        return line
    return "|".join(cell for cell in line.split("|") if not cell.strip().startswith(">"))


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
            # FIX-GRAPHVAL (2026-06-03, Codex REDIRECT on packet 108): strip the quoted target cells FIRST,
            # then apply BOTH the scope-qualifier check AND the absolute-claim check to the audit's OWN
            # remaining content. Otherwise a scope qualifier (`scope`/`coverage`/`within the analyzed`/...)
            # that happens to appear INSIDE a `>`-quoted target excerpt would suppress the WHOLE line and let
            # an unscoped audit claim in ANOTHER cell of the same row evade the gate.
            scan_target = strip_quoted_table_cells(line)
            if line_is_scoped(scan_target):
                continue
            if any(pattern.search(scan_target) for pattern in ABSOLUTE_PATTERNS):
                errors.append(f"anti_overclaim: {relative}:{number}: absolute claim must be scoped by coverage/profile")
    return errors
