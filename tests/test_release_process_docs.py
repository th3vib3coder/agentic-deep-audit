from __future__ import annotations

from agentic_deep_audit.models import PLUGIN_ROOT


RELEASE_PROCESS = PLUGIN_ROOT / "docs" / "contracts" / "release_process.md"
CHECKLIST = PLUGIN_ROOT / "RELEASE_CHECKLIST.md"


def test_release_process_doc_covers_redirect_block_rollback() -> None:
    lowered = RELEASE_PROCESS.read_text(encoding="utf-8").lower()  # FileNotFoundError when absent (RED)
    for section in (
        "redirect",
        "block",
        "failed release gate",
        "post-go implementation failure",
        "rollback",
    ):
        assert section in lowered, f"release_process.md missing required content: {section!r}"


def test_release_process_doc_requires_distinct_reviewer() -> None:
    lowered = RELEASE_PROCESS.read_text(encoding="utf-8").lower()
    assert "distinct reviewer" in lowered or "different from the author" in lowered, (
        "release_process.md must state the distinct-reviewer (no self-ACCEPT) requirement"
    )


def test_release_checklist_has_demotion_procedure() -> None:
    lowered = CHECKLIST.read_text(encoding="utf-8").lower()
    assert "demotion" in lowered, "RELEASE_CHECKLIST.md must document a demotion procedure"
    for column in ("old status", "new status", "evidence", "next review gate"):
        assert column in lowered, f"checklist demotion table missing column: {column}"
