"""Shared helper: extract a wiki page's DECLARED evidence ids from its frontmatter `evidence_ids` list.

Single source of truth used by BOTH the canonical-graph builder (audit_canonical_graph) and the corpus
indexer (audit_corpus) — previously duplicated as `wiki_frontmatter_evidence_ids` / `trusted_wiki_evidence_ids`
(swarm-flagged drift risk). It reads ONLY the structured frontmatter field, never a blanket regex over page
text, so a coincidental "ev-NNNNNN" substring in a slug/title/link is not harvested as a phantom evidence
reference (see FIX-GRAPHVAL, hermes-agent). A leaf module (only stdlib deps) so both importers stay cycle-free.
"""

from __future__ import annotations

import json
import re

_EVIDENCE_RE = re.compile(r"ev-\d{6,}")


def frontmatter_evidence_ids(text: str) -> list[str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.startswith("evidence_ids:"):
            continue
        raw_value = line.split(":", 1)[1].strip()
        try:
            values = json.loads(raw_value)
        except json.JSONDecodeError:
            return []
        if not isinstance(values, list):
            return []
        return sorted({str(item) for item in values if isinstance(item, str) and _EVIDENCE_RE.fullmatch(item)})
    return []
