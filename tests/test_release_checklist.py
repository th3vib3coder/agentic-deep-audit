from __future__ import annotations

import re

from agentic_deep_audit.models import PLUGIN_ROOT


CHECKLIST = PLUGIN_ROOT / "RELEASE_CHECKLIST.md"


def _section(heading: str) -> str:
    text = CHECKLIST.read_text(encoding="utf-8")
    match = re.search(rf"##\s+{re.escape(heading)}\b(.*?)(?=\n##\s|\Z)", text, re.DOTALL)
    return match.group(1) if match else ""


def test_os_evidence_table_has_required_columns() -> None:
    section = _section("OS Evidence").lower()
    assert section, "RELEASE_CHECKLIST.md must have an '## OS Evidence' section"
    for column in ("runner", "shell", "python", "command output", "commit sha", "status"):
        assert column in section, f"OS Evidence table missing column: {column}"


def test_os_evidence_covers_windows_and_ubuntu() -> None:
    section = _section("OS Evidence")
    assert "ubuntu-latest" in section, "OS Evidence must have an ubuntu-latest row"
    assert "windows-latest" in section, "OS Evidence must have a windows-latest row"


def test_macos_row_is_deferred_sd4() -> None:
    section = _section("OS Evidence")
    assert "macos-latest" in section, "OS Evidence must list macos-latest"
    assert "deferred" in section.lower(), "macos-latest must be marked deferred"
    assert "SD-4" in section, "macos-latest deferral must cite SD-4"
