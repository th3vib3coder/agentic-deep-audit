from __future__ import annotations

from agentic_deep_audit.models import PLUGIN_ROOT


CI_DOC = PLUGIN_ROOT / "docs" / "adapters" / "ci.md"

NINE_FIELDS = (
    "adapter id",
    "user entry command",
    "required files",
    "optional files",
    "output directory",
    "security model",
    "expected skipped/deferred behavior",
    "validation command",
    "ownership of docs/tests",
)


def test_ci_doc_has_nine_fields_and_both_shells() -> None:
    text = CI_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"ci.md missing field sections: {missing}"
    assert "```bash" in text, "ci.md must carry a fenced bash code block"
    assert "```powershell" in text, "ci.md must carry a fenced powershell code block"


def test_ci_doc_rejects_path_leakage() -> None:
    # 006 unambiguously-private tokens. NOT REVIEW_LEDGER, which is a shipped engine identifier.
    text = CI_DOC.read_text(encoding="utf-8")
    private = [tok for tok in ("piano_doc", "plugins/agentic-deep-audit", "013_ledger") if tok in text]
    assert not private, f"ci.md leaks private planning tokens: {private}"


def test_ci_doc_snippet_has_help_and_collect_only() -> None:
    text = CI_DOC.read_text(encoding="utf-8")
    assert "--help" in text, "ci.md snippets must include a CLI --help smoke"
    assert "--collect-only" in text, "ci.md snippets must include the collect-only gate"
