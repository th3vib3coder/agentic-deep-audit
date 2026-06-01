"""SEQ-URL-006 / SEQ-009 - Source-of-truth and packaging tests.

REMEDIATION-002 / Codex 016 F4: verifies the slash command file lives in the
plugin source-of-truth path and references the threat-model anchor.
Distribution to the installed plugin bundle is governed by the Codex CLI
plugin convention (Q-NEW-4 in 012) and is intentionally not asserted from
this lane — see `test_command_distributed_to_plugin_bundle`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
COMMAND_DOC = PLUGIN_ROOT / "commands" / "deep-repo-audit.md"


def test_command_in_source_of_truth() -> None:
    """Source-of-truth path: `<plugin>/commands/deep-repo-audit.md` must exist."""
    assert COMMAND_DOC.exists(), (
        f"source-of-truth slash command missing: {COMMAND_DOC}"
    )
    assert COMMAND_DOC.is_file(), f"expected a file, got: {COMMAND_DOC}"


def test_command_distributed_to_plugin_bundle() -> None:
    """Codex CLI plugin sync is opaque to this test lane (Q-NEW-4)."""
    pytest.skip(
        "Codex CLI plugin sync mechanism not testable in this lane per Q-NEW-4"
    )


def test_command_doc_links_to_threat_model() -> None:
    """Doc must reference the threat-model anchor (003 or 003b)."""
    text = COMMAND_DOC.read_text(encoding="utf-8")
    anchors = (
        "003_threat_model_url.md",
        "003b_network_policy_exception.md",
    )
    assert any(anchor in text for anchor in anchors), (
        "command doc must reference at least one threat-model anchor: "
        f"{anchors}"
    )
