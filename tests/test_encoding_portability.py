from __future__ import annotations

import pytest

from agentic_deep_audit.config import ConfigError, load_config_file
from agentic_deep_audit.limits import read_text_auto_capped
from agentic_deep_audit.models import PLUGIN_ROOT


FIXTURES = PLUGIN_ROOT / "tests" / "fixtures" / "encoding_portability"
ENCODING_POLICY_DOC = PLUGIN_ROOT / "docs" / "contracts" / "encoding_policy.md"


def test_utf8_fixture_loads_cleanly() -> None:
    text = read_text_auto_capped(FIXTURES / "utf8.txt")  # FileNotFoundError when absent (RED)
    assert "café" in text


def test_utf8_bom_strips_bom() -> None:
    text = read_text_auto_capped(FIXTURES / "utf8_bom.txt")
    assert not text.startswith("﻿"), "UTF-8 BOM must be stripped on decode"
    assert "café with BOM" in text


def test_crlf_normalizes() -> None:
    text = read_text_auto_capped(FIXTURES / "crlf.txt", normalize_newlines=True)
    assert "\r" not in text, "CRLF must normalize to LF when normalize_newlines=True"
    assert text == "line one\nline two\nthird\n"


def test_lf_passes() -> None:
    text = read_text_auto_capped(FIXTURES / "lf.txt", normalize_newlines=True)
    assert text == "line one\nline two\nthird\n"


def test_non_utf8_config_raises_clear_error() -> None:
    with pytest.raises(ConfigError) as excinfo:
        load_config_file(FIXTURES / "non_utf8.bin")
    assert "utf-8" in str(excinfo.value).lower(), f"error must name the encoding clearly: {excinfo.value}"


def test_non_utf8_source_degrades_without_crash() -> None:
    # Best-effort extraction of an untrusted source file must not crash; invalid bytes degrade
    # deterministically to the Unicode replacement character.
    text = read_text_auto_capped(FIXTURES / "non_utf8.bin", errors="replace")
    assert isinstance(text, str)
    assert "�" in text


def test_encoding_policy_doc_covers_all_cases() -> None:
    lowered = ENCODING_POLICY_DOC.read_text(encoding="utf-8").lower()  # FileNotFoundError when absent (RED)
    for token in ("utf-8", "bom", "crlf", "lf", "diagnostic", "degrade", "replacement character"):
        assert token in lowered, f"encoding_policy.md missing case token: {token!r}"
