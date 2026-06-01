"""SEQ-URL-006 / SEQ-009 - Slash command documentation tests.

Verifies the source-of-truth slash command file
`commands/deep-repo-audit.md` declares the URL Mode
and preserves the Local Path Mode behaviour. ACs 1-9 are sourced from
`url_workflow/009_seq_slash_command_extension.md`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
COMMAND_DOC = PLUGIN_ROOT / "commands" / "deep-repo-audit.md"


@pytest.fixture(scope="module")
def doc_text() -> str:
    assert COMMAND_DOC.exists(), f"command doc missing: {COMMAND_DOC}"
    return COMMAND_DOC.read_text(encoding="utf-8")


def _frontmatter_raw(text: str) -> str:
    parts = text.split("---")
    # Frontmatter sits between the first two `---` markers; parts[0] is the
    # pre-frontmatter chunk (empty when the file starts with `---`).
    assert len(parts) >= 3, "frontmatter delimiters missing"
    return parts[1]


def test_argument_hint_includes_url(doc_text: str) -> None:
    """AC-1: argument-hint frontmatter mentions GitHub URL and target path."""
    hint_line = None
    for line in doc_text.splitlines():
        if line.strip().startswith("argument-hint"):
            hint_line = line
            break
    assert hint_line is not None, "argument-hint line not found"
    assert "URL" in hint_line, f"argument-hint must mention URL: {hint_line!r}"
    assert "target path" in hint_line, (
        f"argument-hint must mention 'target path': {hint_line!r}"
    )


def test_url_mode_section_present(doc_text: str) -> None:
    """AC-2: explicit `## URL Mode` section header exists."""
    assert re.search(r"^## URL Mode\s*$", doc_text, flags=re.MULTILINE), (
        "missing `## URL Mode` header"
    )


def test_url_mode_has_example_command(doc_text: str) -> None:
    """AC-3: URL Mode shows the example invocation."""
    assert "deep-audit url https://github.com/" in doc_text, (
        "URL Mode must show `deep-audit url https://github.com/...` example"
    )


def test_url_mode_references_profile(doc_text: str) -> None:
    """AC-4: documentation references the `standard` profile flag."""
    assert "--profile standard" in doc_text, (
        "URL Mode must reference `--profile standard`"
    )


def test_safety_section_mentions_untrusted(doc_text: str) -> None:
    """AC-5: documentation flags the target repository as untrusted."""
    assert "untrusted" in doc_text, "documentation must mention 'untrusted'"


def test_sandbox_clone_path_referenced(doc_text: str) -> None:
    """AC-6: sandbox clone path `_clone/` documented."""
    assert "_clone/" in doc_text, "documentation must reference `_clone/` sandbox path"


def test_local_path_mode_section_present(doc_text: str) -> None:
    """AC-7: Local Path Mode section preserved."""
    assert re.search(r"^## Local Path Mode\s*$", doc_text, flags=re.MULTILINE), (
        "missing `## Local Path Mode` header"
    )
    assert "deep-audit run --config audit.config.yaml" in doc_text, (
        "Local Path Mode should preserve the existing run command body"
    )


def test_frontmatter_valid_yaml(doc_text: str) -> None:
    """AC-8: YAML frontmatter parses and exposes `description` + `argument-hint`."""
    raw = _frontmatter_raw(doc_text)
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), f"frontmatter must be a mapping, got {type(parsed)}"
    assert "description" in parsed, "frontmatter missing `description` key"
    assert "argument-hint" in parsed, "frontmatter missing `argument-hint` key"


def test_file_under_200_lines(doc_text: str) -> None:
    """AC-9: doc length stays under the 200-line ceiling per spec."""
    line_count = doc_text.count("\n") + (0 if doc_text.endswith("\n") else 1)
    assert line_count < 200, f"command doc must stay under 200 lines, got {line_count}"
