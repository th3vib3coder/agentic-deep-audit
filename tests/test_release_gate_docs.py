from __future__ import annotations

import re
from pathlib import Path

from agentic_deep_audit.models import PLUGIN_ROOT


PS_DOC = PLUGIN_ROOT / "docs" / "contracts" / "release_gates_powershell.md"
BASH_DOC = PLUGIN_ROOT / "docs" / "contracts" / "release_gates_bash.md"

# Each release gate -> token(s) that must all appear (case-insensitive) in a
# cross-shell release-gate doc. Tokens are grounded in 006 (test matrix +
# concrete scan commands + package-manager install gate).
GATE_TOKENS = {
    "public-root scan": ["public-root scan"],
    "adapter path scan": ["adapter path scan"],
    "wheel install smoke": ["pip wheel", "deep-audit"],
    "unit suite": ["pytest tests"],
    "collect-only": ["--collect-only"],
    "CLI smoke": ["agentic_deep_audit.cli --help"],
}


def _assert_doc_covers_gates(doc: Path) -> None:
    text = doc.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [gate for gate, tokens in GATE_TOKENS.items() if not all(tok.lower() in lowered for tok in tokens)]
    assert not missing, f"{doc.name} missing gate coverage: {missing}"


def test_powershell_doc_covers_all_gates() -> None:
    _assert_doc_covers_gates(PS_DOC)


def test_bash_doc_covers_all_gates() -> None:
    _assert_doc_covers_gates(BASH_DOC)


# Unambiguously-private markers (006 §Forbidden CONTENT TOKENS). NOT the engine
# identifiers REVIEW_LEDGER / operator_go, which legitimately appear in shipped source.
# The scan commands quoted in these docs contain some of these tokens, so they are
# allowed only inside fenced code blocks — the prose must stay clean.
PRIVATE_TOKENS = ["piano_doc", "plugins/agentic-deep-audit", "013_ledger", "nuove_skill", "HAT 2"]


def _strip_fenced_blocks(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def test_gate_docs_reject_private_path_tokens() -> None:
    for doc in (PS_DOC, BASH_DOC):
        prose = _strip_fenced_blocks(doc.read_text(encoding="utf-8"))
        present = [tok for tok in PRIVATE_TOKENS if tok in prose]
        assert not present, f"{doc.name} prose (outside fenced scan examples) contains private tokens: {present}"
